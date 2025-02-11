// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	gcorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// HandleBuilder implements builder pattern that builds admission handle.
type HandleBuilder struct {
	mgr                     manager.Manager
	logger                  logr.Logger
	lakomConfig             config.Config
	cacheTTL                time.Duration
	cacheRefreshInterval    time.Duration
	useOnlyImagePullSecrets bool
	allowUntrustedImages    bool
	allowInsecureRegistries bool
}

// NewHandleBuilder returns new handle builder.
func NewHandleBuilder() HandleBuilder {
	hb := HandleBuilder{}
	return hb
}

// WithManager sets the manager.
func (hb HandleBuilder) WithManager(mgr manager.Manager) HandleBuilder {
	hb.mgr = mgr
	return hb
}

// WithUseOnlyImagePullSecrets sets only the artifact pull secrets to be used to access the OCI Registry.
func (hb HandleBuilder) WithUseOnlyImagePullSecrets(useOnlyImagePullSecrets bool) HandleBuilder {
	hb.useOnlyImagePullSecrets = useOnlyImagePullSecrets
	return hb
}

// WithAllowUntrustedImages configures the webhook to allow artifacts without trusted signature.
func (hb HandleBuilder) WithAllowUntrustedImages(allowUntrustedImages bool) HandleBuilder {
	hb.allowUntrustedImages = allowUntrustedImages
	return hb
}

// WithAllowInsecureRegistries configures lakom to communicate via HTTP with registries if HTTPS is not possible
func (hb HandleBuilder) WithAllowInsecureRegistries(allowInsecureRegistries bool) HandleBuilder {
	hb.allowInsecureRegistries = allowInsecureRegistries
	return hb
}

// WithLakomConfig sets the lakom config with the public keys and their properties.
func (hb HandleBuilder) WithLakomConfig(config config.Config) HandleBuilder {
	hb.lakomConfig = config
	return hb
}

// WithCacheTTL sets the TTL for the cache.
func (hb HandleBuilder) WithCacheTTL(ttl time.Duration) HandleBuilder {
	hb.cacheTTL = ttl
	return hb
}

// WithCacheRefreshInterval sets the refresh interval for the cache.
func (hb HandleBuilder) WithCacheRefreshInterval(refreshInterval time.Duration) HandleBuilder {
	hb.cacheRefreshInterval = refreshInterval
	return hb
}

// WithLogger sets the logger.
func (hb HandleBuilder) WithLogger(logger logr.Logger) HandleBuilder {
	hb.logger = logger
	return hb
}

// Build builds a handler from the HandleBuilder.
func (hb HandleBuilder) Build() (*handler, error) {
	var (
		h = handler{
			logger:                  hb.logger,
			reader:                  hb.mgr.GetAPIReader(),
			decoder:                 admission.NewDecoder(hb.mgr.GetScheme()),
			useOnlyImagePullSecrets: hb.useOnlyImagePullSecrets,
			allowUntrustedImages:    hb.allowUntrustedImages,
		}
		verifier Verifier
	)

	lakomConfig, err := hb.lakomConfig.Complete()
	if err != nil {
		return nil, err
	}

	verifier = NewDirectVerifier(*lakomConfig, hb.allowInsecureRegistries)
	if hb.cacheTTL != 0 {
		cache, err := NewSignatureVerificationResultCache(hb.cacheRefreshInterval, hb.cacheTTL)
		if err != nil {
			return nil, err
		}
		verifier = NewCacheVerifier(cache, verifier)
	}
	h.verifier = verifier

	return &h, nil
}

type handler struct {
	reader  client.Reader
	decoder admission.Decoder
	logger  logr.Logger

	verifier                Verifier
	useOnlyImagePullSecrets bool
	allowUntrustedImages    bool
}

var (
	podGVK                  = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controllerDeploymentGVK = metav1.GroupVersionKind{Group: "core.gardener.cloud", Kind: "ControllerDeployment", Version: "v1"}
	gardenletGVK            = metav1.GroupVersionKind{Group: "seedmanagement.gardener.cloud", Kind: "Gardenlet", Version: "v1alpha1"}
	extensionGVK            = metav1.GroupVersionKind{Group: "extensions.operator.gardener.cloud", Kind: "Extension", Version: "v1alpha1"}
	allowedResources        = sets.New(podGVK, controllerDeploymentGVK, gardenletGVK, extensionGVK)
	controlledOperations    = sets.NewString(string(admissionv1.Create), string(admissionv1.Update))
)

func (h *handler) GetLogger() logr.Logger {
	return h.logger
}

// a verification target represents an artifact that needs to be verified
// along with the path from which it was extracted in the resource.
type verificationTarget struct {
	artifactRef string
	fldPath     *field.Path
}

// Handle handles admission requests. It works only on create/update on one of:
// - v1.Pod
// - core.gardener.cloud/ControllerDeployment/v1
// - seedmanagement.gardener.cloud/Gardenlet/v1alpha1
// - extensions.operator.gardener.cloud/Extension/v1alpha1
// and ignores anything else. Ensures that each resource is using images or
// helm charts signed by at least one of the provided public cosign keys.
//
// The resource from the request is first transformed into a list of verification targets.
// After that, each verification target is validated against the provided public keys.
func (h *handler) Handle(ctx context.Context, request admission.Request) admission.Response {
	var (
		err                 error
		verificationTargets []verificationTarget
		kcr                 utils.KeyChainReader
	)
	ctx, cancel := context.WithTimeout(ctx, time.Second*25)
	defer cancel()

	if !allowedResources.Has(request.Kind) {
		return admission.Allowed(fmt.Sprintf("resource is not one of %v", allowedResources.UnsortedList()))
	}

	if request.SubResource != "" && request.SubResource != "ephemeralcontainers" {
		return admission.Allowed("subresources on pods other than 'ephemeralcontainers' are not handled")
	}

	if !controlledOperations.Has(string(request.Operation)) {
		return admission.Allowed(fmt.Sprintf("operation is not any of %v", controlledOperations.List()))
	}

	logger := h.logger.WithValues(request.Kind.Kind, client.ObjectKey{Namespace: request.Namespace, Name: request.Name})

	switch request.Kind {
	case podGVK:
		pod := corev1.Pod{}
		err = h.decoder.Decode(request, &pod)
		if err != nil {
			break
		}
		verificationTargets, kcr, err = h.extractPodVerificationTargets(ctx, pod)
	case controllerDeploymentGVK:
		controllerDeployment := gcorev1.ControllerDeployment{}
		err = h.decoder.Decode(request, &controllerDeployment)
		if err != nil {
			break
		}
		verificationTargets, kcr, err = h.extractControllerDeploymentVerificationTargets(ctx, controllerDeployment)
	case gardenletGVK:
		gardenlet := seedmanagementv1alpha1.Gardenlet{}
		err = h.decoder.Decode(request, &gardenlet)
		if err != nil {
			break
		}
		verificationTargets, kcr, err = h.extractGardenletVerificationTargets(ctx, gardenlet)
	case extensionGVK:
		extension := operatorv1alpha1.Extension{}
		err = h.decoder.Decode(request, &extension)
		if err != nil {
			break
		}
		verificationTargets, kcr, err = h.extractExtensionVerificationTargets(ctx, extension)
	default:
		return admission.Allowed(fmt.Sprintf("resource is not one of %v", allowedResources.UnsortedList()))
	}

	if err != nil {
		logger.Error(err, "failed to extract verification targets")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if err := h.validateTargets(ctx, logger, verificationTargets, kcr); err != nil {
		if h.allowUntrustedImages {
			logger.Info("resource validation failed but untrusted artifacts are allowed", "error", err.Error())
			warningResponse := admission.Allowed("untrusted artifacts are allowed")
			warningResponse.Warnings = []string{
				fmt.Sprintf("Failed to admit resource with error: %q", err.Error()),
			}
			return warningResponse
		}
		logger.Error(err, "resource validation failed")
		return admission.Denied(err.Error())
	}

	return admission.Allowed("All artifacts successfully validated with cosign public keys")
}

// extractPodVerificationTargets returns an array of verification targets from the pod.
// The verification targets are extracted from the following fields:
// - v1.Pod: spec.initContainers[*].image
// - v1.Pod: spec.containers[*].image
// - v1.Pod: spec.ephemeralContainers[*].image
func (h *handler) extractPodVerificationTargets(ctx context.Context, pod corev1.Pod) ([]verificationTarget, utils.KeyChainReader, error) {
	var verificationTargets []verificationTarget
	kcr := utils.NewLazyKeyChainReaderFromPod(ctx, h.reader, &pod, h.useOnlyImagePullSecrets)

	specPath := field.NewPath("pod", "spec")
	for idx, ic := range pod.Spec.InitContainers {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: ic.Image,
			fldPath:     specPath.Child("initContainers").Index(idx).Child("image"),
		})
	}
	for idx, c := range pod.Spec.Containers {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: c.Image,
			fldPath:     specPath.Child("containers").Index(idx).Child("image"),
		})
	}
	for idx, ec := range pod.Spec.EphemeralContainers {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: ec.Image,
			fldPath:     specPath.Child("ephemeralContainers").Index(idx).Child("image"),
		})
	}

	return verificationTargets, kcr, nil
}

// extractControllerDeploymentVerificationTargets returns an array of verification targets from the controller deployment.
// The verification targets are extracted from the following fields:
// - core.gardener.cloud/ControllerDeployment: helm.ociRepository
func (h *handler) extractControllerDeploymentVerificationTargets(ctx context.Context, controllerDeployment gcorev1.ControllerDeployment) ([]verificationTarget, utils.KeyChainReader, error) {
	var verificationTargets []verificationTarget

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, controllerDeployment.Namespace, []string{}, h.useOnlyImagePullSecrets)

	if controllerDeployment.Helm != nil && controllerDeployment.Helm.OCIRepository != nil {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: controllerDeployment.Helm.OCIRepository.GetURL(),
			fldPath:     field.NewPath("helm", "ociRepository"),
		})
	}

	return verificationTargets, kcr, nil
}

// extractGardenletVerificationTargets returns an array of verification targets from the gardenlet.
// The verification targets are extracted from the following fields:
// - seedmanagement.gardener.cloud/Gardenlet: spec.deployment.helm.ociRepository
// - seedmanagement.gardener.cloud/Gardenlet: spec.deployment.image
func (h *handler) extractGardenletVerificationTargets(ctx context.Context, gardenlet seedmanagementv1alpha1.Gardenlet) ([]verificationTarget, utils.KeyChainReader, error) {
	var verificationTargets []verificationTarget

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, gardenlet.Namespace, []string{}, h.useOnlyImagePullSecrets)

	verificationTargets = append(verificationTargets, verificationTarget{
		artifactRef: gardenlet.Spec.Deployment.Helm.OCIRepository.GetURL(),
		fldPath:     field.NewPath("spec", "deployment", "helm", "ociRepository"),
	})
	if gardenlet.Spec.Deployment.Image != nil {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: getURL(gardenlet.Spec.Deployment.Image),
			fldPath:     field.NewPath("spec", "deployment", "image"),
		})
	}

	return verificationTargets, kcr, nil
}

// extractExtensionVerificationTargets returns an array of verification targets from the extension.
// The verification targets are extracted from the following fields:
// - extensions.operator.gardener.cloud/Extension: spec.deployment.admission.runtimeCluster.helm.ociRepository
// - extensions.operator.gardener.cloud/Extension: spec.deployment.admission.virtualCluster.helm.ociRepository
// - extensions.operator.gardener.cloud/Extension: spec.deployment.extension.helm.ociRepository
func (h *handler) extractExtensionVerificationTargets(ctx context.Context, extension operatorv1alpha1.Extension) ([]verificationTarget, utils.KeyChainReader, error) {
	var verificationTargets []verificationTarget

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, extension.Namespace, []string{}, h.useOnlyImagePullSecrets)

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository != nil {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.GetURL(),
			fldPath:     field.NewPath("spec", "deployment", "admissionDeployment", "runtimeCluster", "helm", "ociRepository"),
		})
	}

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository != nil {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.GetURL(),
			fldPath:     field.NewPath("spec", "deployment", "admissionDeployment", "virtualCluster", "helm", "ociRepository"),
		})
	}

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.ExtensionDeployment != nil &&
		extension.Spec.Deployment.ExtensionDeployment.Helm != nil &&
		extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository != nil {
		verificationTargets = append(verificationTargets, verificationTarget{
			artifactRef: extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.GetURL(),
			fldPath:     field.NewPath("spec", "deployment", "extensionDeployment", "helm", "ociRepository"),
		})
	}

	return verificationTargets, kcr, nil
}

// getURL returns the fully-qualified OCIRepository URL of the image.
func getURL(img *seedmanagementv1alpha1.Image) string {
	ref := *img.Repository

	if img.Tag != nil {
		ref = ref + ":" + *img.Tag
	}

	return strings.TrimPrefix(ref, "oci://")
}

func (h *handler) validateTargets(ctx context.Context, logger logr.Logger, verificationTargets []verificationTarget, kcr utils.KeyChainReader) error {
	var (
		errorList           = field.ErrorList{}
		noSignatureFoundMsg = "no valid signature found"
	)

	for _, verificationTarget := range verificationTargets {
		verified, err := h.validateArtifact(ctx, logger, verificationTarget.artifactRef, kcr)
		if err != nil {
			errorList = append(errorList, field.InternalError(verificationTarget.fldPath, err))
		} else if !verified {
			errorList = append(errorList, field.Forbidden(verificationTarget.fldPath, fmt.Sprintf("%s for artifact %s", noSignatureFoundMsg, verificationTarget.artifactRef)))
		}
	}

	return errorList.ToAggregate()
}

func (h *handler) validateArtifact(ctx context.Context, logger logr.Logger, artifact string, kcr utils.KeyChainReader) (bool, error) {
	ctx = logf.IntoContext(ctx, logger)

	verified, err := h.verifier.Verify(ctx, artifact, kcr)
	if err != nil {
		metrics.ImageSignatureErrors.WithLabelValues().Inc()
	} else {
		metrics.ImageSignature.WithLabelValues(strconv.FormatBool(verified)).Inc()
	}

	return verified, err
}

// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// HandleBuilder implements builder pattern that builds admission handle.
type HandleBuilder struct {
	mgr                     manager.Manager
	logger                  logr.Logger
	cacheTTL                time.Duration
	cacheRefreshInterval    time.Duration
	useOnlyImagePullSecrets bool
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

// WithUseOnlyImagePullSecrets sets only the image pull secrets to be used to access the OCI Registry.
func (hb HandleBuilder) WithUseOnlyImagePullSecrets(useOnlyImagePullSecrets bool) HandleBuilder {
	hb.useOnlyImagePullSecrets = useOnlyImagePullSecrets
	return hb
}

// WithAllowInsecureRegistries allows Lakom to use HTTP for communication with the registries
func (hb HandleBuilder) WithAllowInsecureRegistries(allowInsecureRegistries bool) HandleBuilder {
	hb.allowInsecureRegistries = allowInsecureRegistries
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
			allowInsecureRegistries: hb.allowInsecureRegistries,
		}
		resolver Resolver
	)

	resolver = NewDirectResolver()
	if hb.cacheTTL != 0 {
		cache, err := NewDigestCache(hb.cacheRefreshInterval, hb.cacheTTL)
		if err != nil {
			return nil, err
		}
		resolver = NewCacheResolver(cache, resolver)
	}
	h.resolver = resolver

	return &h, nil
}

type handler struct {
	reader  client.Reader
	decoder admission.Decoder
	logger  logr.Logger

	resolver                Resolver
	useOnlyImagePullSecrets bool
	allowInsecureRegistries bool
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

// Handle handles admission requests. It works on create/update on the following resources:
// - v1/Pod
// - core.gardener.cloud/v1/ControllerDeployment
// - seedmanagement.gardener.cloud/v1alpha1/Gardenlet
// - extensions.operator.gardener.cloud/v1alpha1/Extension
func (h *handler) Handle(ctx context.Context, request admission.Request) admission.Response {
	var (
		patch []byte
		err   error
	)

	ctx, cancel := context.WithTimeout(ctx, time.Second*25)
	defer cancel()

	if !controlledOperations.Has(string(request.Operation)) {
		return admission.Allowed(fmt.Sprintf("operation is not any of %v", controlledOperations.List()))
	}

	switch request.Kind {
	case podGVK:
		if request.SubResource != "" && request.SubResource != "ephemeralcontainers" {
			return admission.Allowed("subresources on pods other than 'ephemeralcontainers' are not handled")
		}
		pod := corev1.Pod{}
		err = h.decoder.Decode(request, &pod)
		if err != nil {
			break
		}
		patch, err = h.handlePod(ctx, pod)
	case controllerDeploymentGVK:
		controllerDeployment := gardencorev1.ControllerDeployment{}
		err = h.decoder.Decode(request, &controllerDeployment)
		if err != nil {
			break
		}
		patch, err = h.handleControllerDeployment(ctx, controllerDeployment)
	case gardenletGVK:
		gardenlet := seedmanagementv1alpha1.Gardenlet{}
		err = h.decoder.Decode(request, &gardenlet)
		if err != nil {
			break
		}
		patch, err = h.handleGardenlet(ctx, gardenlet)
	case extensionGVK:
		extension := operatorv1alpha1.Extension{}
		err = h.decoder.Decode(request, &extension)
		if err != nil {
			break
		}
		patch, err = h.handleExtension(ctx, extension)
	default:
		return admission.Allowed(fmt.Sprintf("resource is not one of %v", allowedResources.UnsortedList()))
	}

	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(request.Object.Raw, patch)
}

// Ensures that each OCIRepository URL in the gardenlet is referring
// to an artifact using digest instead of tag.
// The following fields are checked:
// - gardenlet.Spec.Deployment.Helm.OCIRepository
// - gardenlet.Spec.Deployment.Image
func (h *handler) handleGardenlet(ctx context.Context, gardenlet seedmanagementv1alpha1.Gardenlet) ([]byte, error) {
	var (
		logger           = h.logger.WithValues("gardenlet", client.ObjectKey{Name: gardenlet.Name})
		imagePullSecrets []string
	)

	if gardenlet.Spec.Deployment.Helm.OCIRepository.PullSecretRef != nil {
		imagePullSecrets = append(imagePullSecrets, gardenlet.Spec.Deployment.Helm.OCIRepository.PullSecretRef.Name)
	}

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, v1beta1constants.GardenNamespace, imagePullSecrets, h.useOnlyImagePullSecrets)

	resolved, err := h.resolveArtifact(ctx, gardenlet.Spec.Deployment.Helm.OCIRepository.GetURL(), kcr, logger)
	if err != nil {
		return nil, err
	}
	gardenlet.Spec.Deployment.Helm.OCIRepository.Ref = &resolved.ref

	if gardenlet.Spec.Deployment.Image != nil {
		resolved, err := h.resolveArtifact(ctx, getURL(gardenlet.Spec.Deployment.Image), kcr, logger)
		if err != nil {
			return nil, err
		}
		gardenlet.Spec.Deployment.Image.Repository = &resolved.repository
		gardenlet.Spec.Deployment.Image.Tag = &resolved.digest
	}

	return json.Marshal(gardenlet)
}

// Ensures that each OCIRepository URL in the controller deployment is referring
// to an artifact using digest instead of tag.
// The following fields are checked:
// - controllerDeployment.Spec.Helm.OCIRepository
func (h *handler) handleControllerDeployment(ctx context.Context, controllerDeployment gardencorev1.ControllerDeployment) ([]byte, error) {
	var (
		logger           = h.logger.WithValues("controllerDeployment", client.ObjectKey{Name: controllerDeployment.Name})
		imagePullSecrets []string
	)

	if controllerDeployment.Helm.OCIRepository.PullSecretRef != nil {
		imagePullSecrets = append(imagePullSecrets, controllerDeployment.Helm.OCIRepository.PullSecretRef.Name)
	}

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, v1beta1constants.GardenNamespace, imagePullSecrets, h.useOnlyImagePullSecrets)

	if controllerDeployment.Helm != nil && controllerDeployment.Helm.OCIRepository != nil {
		resolved, err := h.resolveArtifact(ctx, controllerDeployment.Helm.OCIRepository.GetURL(), kcr, logger)
		if err != nil {
			return nil, err
		}

		controllerDeployment.Helm.OCIRepository.Ref = &resolved.ref
	}

	return json.Marshal(controllerDeployment)
}

// Ensures that each OCIRepository URL in the extension resource is referring
// to an artifact using digest instead of tag.
// The following fields are checked:
// - extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository
// - extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository
// - extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository
func (h *handler) handleExtension(ctx context.Context, extension operatorv1alpha1.Extension) ([]byte, error) {
	var (
		logger           = h.logger.WithValues("extension", client.ObjectKey{Name: extension.Name})
		imagePullSecrets []string
	)

	if extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.PullSecretRef != nil {
		imagePullSecrets = append(imagePullSecrets, extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.PullSecretRef.Name)
	}

	if extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.PullSecretRef != nil {
		imagePullSecrets = append(imagePullSecrets, extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.PullSecretRef.Name)
	}

	if extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.PullSecretRef != nil {
		imagePullSecrets = append(imagePullSecrets, extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.PullSecretRef.Name)
	}

	kcr := utils.NewLazyKeyChainReaderFromSecrets(ctx, h.reader, v1beta1constants.GardenNamespace, imagePullSecrets, h.useOnlyImagePullSecrets)

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm != nil &&
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository != nil {
		resolved, err := h.resolveArtifact(ctx, extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.GetURL(), kcr, logger)
		if err != nil {
			return nil, err
		}
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.Ref = &resolved.ref
	}

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm != nil &&
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository != nil {
		resolved, err := h.resolveArtifact(ctx, extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.GetURL(), kcr, logger)
		if err != nil {
			return nil, err
		}
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.Ref = &resolved.ref
	}

	if extension.Spec.Deployment != nil &&
		extension.Spec.Deployment.ExtensionDeployment != nil &&
		extension.Spec.Deployment.ExtensionDeployment.Helm != nil &&
		extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository != nil {
		resolved, err := h.resolveArtifact(ctx, extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.GetURL(), kcr, logger)
		if err != nil {
			return nil, err
		}
		extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.Ref = &resolved.ref
	}

	return json.Marshal(extension)
}

// Ensures that each initContainer, container and ephemeral container is using digest instead of tag.
func (h *handler) handlePod(ctx context.Context, pod corev1.Pod) ([]byte, error) {
	var (
		logger = h.logger.WithValues("pod", client.ObjectKey{Name: pod.Name})
		kcr    = utils.NewLazyKeyChainReaderFromPod(ctx, h.reader, &pod, h.useOnlyImagePullSecrets)
	)

	for idx, ic := range pod.Spec.InitContainers {
		resolved, err := h.resolveArtifact(ctx, ic.Image, kcr, logger)
		if err != nil {
			return nil, err
		}

		pod.Spec.InitContainers[idx].Image = resolved.ref
	}
	for idx, c := range pod.Spec.Containers {
		resolved, err := h.resolveArtifact(ctx, c.Image, kcr, logger)
		if err != nil {
			return nil, err
		}

		pod.Spec.Containers[idx].Image = resolved.ref
	}
	for idx, ec := range pod.Spec.EphemeralContainers {
		resolved, err := h.resolveArtifact(ctx, ec.Image, kcr, logger)
		if err != nil {
			return nil, err
		}

		pod.Spec.EphemeralContainers[idx].Image = resolved.ref
	}

	return json.Marshal(pod)
}

// getURL returns the fully-qualified OCIRepository URL of the image.
func getURL(img *seedmanagementv1alpha1.Image) string {
	ref := *img.Repository

	if img.Tag != nil {
		if strings.HasPrefix(*img.Tag, "sha256:") {
			ref = ref + "@" + *img.Tag
		} else {
			ref = ref + ":" + *img.Tag
		}
	}

	return strings.TrimPrefix(ref, "oci://")
}

// resolveArtifact resolves OCI image artefact using tag to its sha256 digest.
// It returns the full image reference, the repository and the digest.
func (h *handler) resolveArtifact(ctx context.Context, image string, kcr utils.KeyChainReader, logger logr.Logger) (*resolvedArtefact, error) {
	logger = logger.WithValues("originalImage", image)

	opts := []name.Option{}
	if h.allowInsecureRegistries {
		opts = append(opts, name.Insecure)
	}

	imageRef, err := name.ParseReference(image, opts...)
	if err != nil {
		return nil, err
	}

	if imageDigest, ok := imageRef.(name.Digest); ok {
		logger.Info("Image already using digest")
		return &resolvedArtefact{
			ref:        image,
			repository: imageDigest.Context().Name(),
			digest:     imageDigest.DigestStr(),
		}, nil
	}

	tagRef, ok := imageRef.(name.Tag)
	if !ok {
		return nil, fmt.Errorf("image reference %q cannot be converted to tagReference", imageRef.Name())
	}

	resolved, err := h.resolver.Resolve(ctx, tagRef, kcr)
	if err != nil {
		metrics.ResolvedTagErrors.WithLabelValues().Inc()
		return nil, err
	}

	metrics.ResolvedTag.WithLabelValues().Inc()
	logger.Info("Image has been resolved", "imageWithDigest", resolved)

	digestRef, err := name.NewDigest(resolved, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse resolved reference %q as image using digest: %w", resolved, err)
	}

	return &resolvedArtefact{
		ref:        resolved,
		repository: digestRef.Context().Name(),
		digest:     digestRef.DigestStr(),
	}, nil
}

type resolvedArtefact struct {
	ref        string
	repository string
	digest     string
}

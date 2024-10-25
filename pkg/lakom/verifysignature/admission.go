// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

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

// WithUseOnlyImagePullSecrets sets only the image pull secrets to be used to access the OCI Registry.
func (hb HandleBuilder) WithUseOnlyImagePullSecrets(useOnlyImagePullSecrets bool) HandleBuilder {
	hb.useOnlyImagePullSecrets = useOnlyImagePullSecrets
	return hb
}

// WithAllowUntrustedImages configures the webhook to allow images without trusted signature.
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
	podGVK               = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controlledOperations = sets.NewString(string(admissionv1.Create), string(admissionv1.Update))
)

func (h *handler) GetLogger() logr.Logger {
	return h.logger
}

// Handle handles admission requests. It works only on create/update v1.Pods and ignores anything else.
// Ensures that each initContainer, container and ephemeral container is using images signed by
// at least one of the provided public cosign keys.
func (h *handler) Handle(ctx context.Context, request admission.Request) admission.Response {
	ctx, cancel := context.WithTimeout(ctx, time.Second*25)
	defer cancel()

	if request.Kind != podGVK {
		return admission.Allowed("resource is not v1.Pod")
	}

	if request.SubResource != "" && request.SubResource != "ephemeralcontainers" {
		return admission.Allowed("subresources on pods other than 'ephemeralcontainers' are not handled")
	}

	if !controlledOperations.Has(string(request.Operation)) {
		return admission.Allowed(fmt.Sprintf("operation is not any of %v", controlledOperations.List()))
	}

	pod := &corev1.Pod{}
	if err := h.decoder.Decode(request, pod); err != nil {
		h.logger.Error(err, "failed to decode request to pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	logger := h.logger.WithValues("pod", client.ObjectKeyFromObject(pod))

	if err := h.validatePod(ctx, logger, pod); err != nil {
		if h.allowUntrustedImages {
			logger.Info("pod validation failed but untrusted images are allowed", "error", err.Error())
			warningsResponse := admission.Allowed("untrusted images are allowed")
			warningsResponse.Warnings = []string{
				fmt.Sprintf("Failed to admit pod with error: %q", err.Error()),
			}
			return warningsResponse
		}
		logger.Error(err, "pod validation failed")
		return admission.Denied(err.Error())
	}

	return admission.Allowed("All images successfully validated with cosign public keys")
}

func (h *handler) validatePod(ctx context.Context, logger logr.Logger, p *corev1.Pod) error {
	var (
		specPath            = field.NewPath("pod", "spec")
		errorList           = field.ErrorList{}
		noSignatureFoundMsg = "no valid signature found"
	)

	logger.Info("Handling new pod request")

	kcr := utils.NewLazyKeyChainReaderFromPod(ctx, h.reader, p, h.useOnlyImagePullSecrets)

	for idx, ic := range p.Spec.InitContainers {
		fldPath := specPath.Child("initContainers").Index(idx).Child("image")
		verified, err := h.validateContainerImage(ctx, logger.WithValues("initContainers", ic.Name), ic.Name, ic.Image, kcr)
		if err != nil {
			errorList = append(errorList, field.InternalError(fldPath, err))
		} else if !verified {
			errorList = append(errorList, field.Forbidden(fldPath, fmt.Sprintf("%s for image %s", noSignatureFoundMsg, ic.Image)))
		}
	}

	for idx, c := range p.Spec.Containers {
		fldPath := specPath.Child("containers").Index(idx).Child("image")
		verified, err := h.validateContainerImage(ctx, logger.WithValues("containers", c.Name), c.Name, c.Image, kcr)
		if err != nil {
			errorList = append(errorList, field.InternalError(fldPath, err))
		} else if !verified {
			errorList = append(errorList, field.Forbidden(fldPath, fmt.Sprintf("%s for image %s", noSignatureFoundMsg, c.Image)))
		}
	}

	for idx, ec := range p.Spec.EphemeralContainers {
		fldPath := specPath.Child("ephemeralContainers").Index(idx).Child("image")
		verified, err := h.validateContainerImage(ctx, logger.WithValues("ephemeralContainers", ec.Name), ec.Name, ec.Image, kcr)
		if err != nil {
			errorList = append(errorList, field.InternalError(fldPath, err))
		} else if !verified {
			errorList = append(errorList, field.Forbidden(fldPath, fmt.Sprintf("%s for image %s", noSignatureFoundMsg, ec.Image)))
		}
	}

	return errorList.ToAggregate()
}

func (h *handler) validateContainerImage(ctx context.Context, logger logr.Logger, containerName, image string, kcr utils.KeyChainReader) (bool, error) {
	logger = logger.WithValues("image", image).WithValues("containerName", containerName)
	ctx = logf.IntoContext(ctx, logger)

	verified, err := h.verifier.Verify(ctx, image, kcr)
	if err != nil {
		metrics.ImageSignatureErrors.WithLabelValues().Inc()
	} else {
		metrics.ImageSignature.WithLabelValues(strconv.FormatBool(verified)).Inc()
	}

	return verified, err
}

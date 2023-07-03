// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// HandleBuilder implements builder pattern that builds admission handle.
type HandleBuilder struct {
	logger                 logr.Logger
	cosignPublicKeysReader io.Reader
	cacheTTL               time.Duration
	cacheRefreshInterval   time.Duration
}

// NewHandleBuilder returns new handle builder.
func NewHandleBuilder() HandleBuilder {
	hb := HandleBuilder{}
	return hb
}

// WithCosignPublicKeysReader sets the reader with the cosign public keys.
func (hb HandleBuilder) WithCosignPublicKeysReader(cosignPublicKeysReader io.Reader) HandleBuilder {
	hb.cosignPublicKeysReader = cosignPublicKeysReader
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
func (hb HandleBuilder) Build(_ context.Context) (*handler, error) {
	var (
		h        = handler{logger: hb.logger}
		verifier Verifier
	)

	rawKeys, err := io.ReadAll(hb.cosignPublicKeysReader)
	if err != nil {
		return nil, err
	}

	cosignPublicKeys, err := utils.GetCosignPublicKeys(rawKeys)
	if err != nil {
		return nil, err
	}

	verifier = NewDirectVerifier(cosignPublicKeys)
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
	decoder *admission.Decoder
	logger  logr.Logger

	verifier Verifier
}

// InjectDecoder injects decoder into handler.
func (h *handler) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}

// InjectAPIReader injects k8s readonly client into handler.
func (h *handler) InjectAPIReader(r client.Reader) error {
	h.reader = r
	return nil
}

var (
	podGVK               = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controlledOperations = sets.NewString(string(admissionv1.Create), string(admissionv1.Update))
)

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

	// TODO: Remove namespace population once support for k8s <1.24 is dropped
	// Ref: https://github.com/kubernetes/kubernetes/pull/94637
	if pod.GetNamespace() == "" {
		pod.SetNamespace(request.Namespace)
	}

	logger := h.logger.WithValues("pod", client.ObjectKeyFromObject(pod))

	if err := h.validatePod(ctx, logger, pod); err != nil {
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

	kcr := utils.NewLazyKeyChainReader(func() (authn.Keychain, error) {
		secretRefs := p.Spec.ImagePullSecrets
		var imagePullSecrets = make([]corev1.Secret, len(secretRefs))
		for _, s := range secretRefs {
			secret := &corev1.Secret{}
			secretKey := client.ObjectKey{Namespace: p.GetNamespace(), Name: s.Name}

			if err := h.reader.Get(ctx, secretKey, secret); err != nil {
				return nil, err
			}
			imagePullSecrets = append(imagePullSecrets, *secret)
		}

		return k8schain.NewFromPullSecrets(ctx, imagePullSecrets)
	})

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

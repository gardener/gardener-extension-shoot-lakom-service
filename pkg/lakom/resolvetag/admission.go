// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

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
	podGVK               = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controlledOperations = sets.NewString(string(admissionv1.Create), string(admissionv1.Update))
)

func (h *handler) GetLogger() logr.Logger {
	return h.logger
}

// Handle handles admission requests. It works only on create/update v1.Pods and ignores anything else.
// Ensures that each initContainer, container and ephemeral container is using digest instead of tag.
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

	if err := h.handlePod(ctx, pod, logger); err != nil {
		logger.Error(err, "failed to handle pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	marshaled, err := json.Marshal(pod)
	if err != nil {
		logger.Error(err, "failed to marshal pod mutation")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(request.Object.Raw, marshaled)
}

func (h *handler) handlePod(ctx context.Context, p *corev1.Pod, logger logr.Logger) error {
	logger.Info("Handling new pod request")

	kcr := utils.NewLazyKeyChainReaderFromPod(ctx, h.reader, p, h.useOnlyImagePullSecrets)

	for idx, ic := range p.Spec.InitContainers {
		image, err := h.handleContainer(ctx, ic.Image, kcr, logger.WithValues("initContainer", ic.Name))
		if err != nil {
			return err
		}
		if image != "" {
			p.Spec.InitContainers[idx].Image = image
		}
	}

	for idx, c := range p.Spec.Containers {
		image, err := h.handleContainer(ctx, c.Image, kcr, logger.WithValues("container", c.Name))
		if err != nil {
			return err
		}
		if image != "" {
			p.Spec.Containers[idx].Image = image
		}
	}

	for idx, ec := range p.Spec.EphemeralContainers {
		image, err := h.handleContainer(ctx, ec.Image, kcr, logger.WithValues("ephemeralContainer", ec.Name))
		if err != nil {
			return err
		}
		if image != "" {
			p.Spec.EphemeralContainers[idx].Image = image
		}
	}

	return nil
}

func (h *handler) handleContainer(ctx context.Context, image string, kcr utils.KeyChainReader, logger logr.Logger) (string, error) {
	logger = logger.WithValues("originalImage", image)

	opts := []name.Option{}
	if h.allowInsecureRegistries {
		opts = append(opts, name.Insecure)
	}

	imageRef, err := name.ParseReference(image, opts...)
	if err != nil {
		return "", err
	}

	if _, ok := imageRef.(name.Digest); ok {
		logger.Info("Image already using digest")
		return image, nil
	}

	tagRef, ok := imageRef.(name.Tag)
	if !ok {
		return "", fmt.Errorf("image reference %q cannot be converted to tagReference", imageRef.Name())
	}

	resolved, err := h.resolver.Resolve(ctx, tagRef, kcr)
	if err != nil {
		metrics.ResolvedTagErrors.WithLabelValues().Inc()
		return "", err
	}

	metrics.ResolvedTag.WithLabelValues().Inc()
	logger.Info("Image has been resolved", "imageWithDigest", resolved)

	return resolved, nil
}

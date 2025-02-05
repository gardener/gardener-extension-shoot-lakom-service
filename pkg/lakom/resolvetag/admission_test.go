// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag_test

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/resolvetag"

	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	deploymentGVK = metav1.GroupVersionKind{Group: "apps", Kind: "Deployment", Version: "v1"}
	podGVK        = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	imageTag      = "registry.k8s.io/pause:3.7"
	imageDigest   = "registry.k8s.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c" // #nosec G101
)

var _ = Describe("Admission Handler", func() {
	var (
		ctx     = context.Background()
		logger  logr.Logger
		handler admission.Handler
		pod     = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "pod-namespace",
				Name:      "pod-name",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "container",
					Image: signedImageTagRef,
				}},
			},
		}
		invalidPod = &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "invalida.api/v1",
				Kind:       "InvalidKind",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "invalid-namespace",
				Name:      "invalid-name",
			},
		}
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mgr = mockmanager.NewMockManager(ctrl)
		apiReader = mockclient.NewMockReader(ctrl)

		mgr.EXPECT().GetAPIReader().Return(apiReader)
		mgr.EXPECT().GetScheme().Return(scheme)

		logger = logzap.New(logzap.WriteTo(GinkgoWriter))
		h, err := resolvetag.
			NewHandleBuilder().
			WithManager(mgr).
			WithLogger(logger.WithName("test-image-tag-resolver")).
			WithCacheTTL(time.Minute * 10).
			WithCacheRefreshInterval(time.Second * 30).
			Build()
		Expect(err).ToNot(HaveOccurred())

		handler = h

		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "pod-namespace",
				Name:      "pod-name",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "container",
					Image: signedImageTagRef,
				}},
			},
		}
		imageDigest = signedImageFullRef
	})

	DescribeTable(
		"Resource handling",
		func(request admission.Request, allowed bool, errMsg string) {
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(Equal(allowed))
			if !allowed {
				Expect(response.AdmissionResponse.Result.Message).To(ContainSubstring(errMsg))
				Expect(response.AdmissionResponse.Result.Code).To(BeEquivalentTo(http.StatusInternalServerError))
			}
		},
		Entry("Allow apps/v1.deployments", arb{}.withKind(deploymentGVK).Build(), true, ""),
		Entry("Allow status subResource requests on pods", arb{}.withKind(podGVK).withSubResource("status").Build(), true, ""),
		Entry("Allow update status subResource requests on pods with invalid image", arb{}.withKind(podGVK).withSubResource("status").withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build(), true, ""),
		Entry("Allow delete operation on pods", arb{}.withKind(podGVK).withOperation(admissionv1.Delete).Build(), true, ""),
		Entry("Allow connect operation on pods", arb{}.withKind(podGVK).withOperation(admissionv1.Connect).Build(), true, ""),
		Entry("Disallow undecodable pod", arb{}.withKind(podGVK).withOperation(admissionv1.Create).withObject(invalidPod).Build(), false, `no kind "InvalidKind" is registered for version`),
		Entry("Disallow pod with invalid image", arb{}.withKind(podGVK).withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build(), false, "could not parse reference"),
		Entry("Disallow pod with invalid image via ephemeralcontainers subResource request", arb{}.withKind(podGVK).withSubResource("ephemeralcontainers").withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build(), false, "could not parse reference"),
	)

	It("Should properly resolve tag to digest", func() {
		request := arb{}.withKind(podGVK).withOperation(admissionv1.Create).withObject(pod).Build()
		response := handler.Handle(ctx, request)
		Expect(response.Allowed).To(BeTrue())
		Expect(response.Patches).To(HaveLen(1))
		patch := response.Patches[0]
		Expect(patch.Operation).To(Equal("replace"))
		Expect(patch.Path).To(Equal("/spec/containers/0/image"))
		Expect(patch.Value).To(Equal(imageDigest))
	})

})

func podWithImage(pod *corev1.Pod, image string) *corev1.Pod {
	p := pod.DeepCopy()
	for idx := range p.Spec.InitContainers {
		p.Spec.InitContainers[idx].Image = image
	}

	for idx := range p.Spec.Containers {
		p.Spec.Containers[idx].Image = image
	}

	for idx := range p.Spec.EphemeralContainers {
		p.Spec.EphemeralContainers[idx].Image = image
	}

	return p
}

type arb struct {
	gvk         metav1.GroupVersionKind
	subResource string
	operation   admissionv1.Operation
	object      runtime.RawExtension
}

func (arb arb) withKind(gvk metav1.GroupVersionKind) arb {
	arb.gvk = gvk
	return arb
}

func (arb arb) withSubResource(subResource string) arb {
	arb.subResource = subResource
	return arb
}

func (arb arb) withOperation(operation admissionv1.Operation) arb {
	arb.operation = operation
	return arb
}

func (arb arb) withObject(object runtime.Object) arb {
	arb.object = runtime.RawExtension{Raw: encode(object)}

	return arb
}

func (arb arb) Build() admission.Request {
	request := admission.Request{}

	request.AdmissionRequest.Kind = arb.gvk
	request.AdmissionRequest.SubResource = arb.subResource
	request.AdmissionRequest.Operation = arb.operation
	request.AdmissionRequest.Object = arb.object

	return request
}

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

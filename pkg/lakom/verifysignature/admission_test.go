// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/pkg/mock/controller-runtime/manager"
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
	deploymentGVK   = metav1.GroupVersionKind{Group: "apps", Kind: "Deployment", Version: "v1"}
	podGVK          = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	imageDigest     = "gcr.io/projectsigstore/cosign@sha256:f9fd5a287a67f4b955d08062a966df10f9a600b6b8583fd367bce3f1f000a429"
	cosignPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyQCx0E9wQWSFI9ULGwy3BuRklnt
IqozONbbdbqz11hlRJy9c7SG+hdcFl9jE9uE/dwtuwU2MqU9T/cN0YkWww==
-----END PUBLIC KEY-----
`

	scheme    *runtime.Scheme
	ctrl      *gomock.Controller
	mgr       *mockmanager.MockManager
	apiReader *mockclient.MockReader
)

var _ = BeforeSuite(func() {
	scheme = runtime.NewScheme()
	err := corev1.AddToScheme(scheme)
	Expect(err).ToNot(HaveOccurred())

	dirPath, err := os.MkdirTemp("", "verifysignature_test")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := os.RemoveAll(dirPath)
		Expect(err).ToNot(HaveOccurred())
	})
})

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
					Image: imageDigest,
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
		reader := strings.NewReader(cosignPublicKey)
		h, err := verifysignature.
			NewHandleBuilder().
			WithManager(mgr).
			WithLogger(logger.WithName("test-cosign-signature-verifier")).
			WithCosignPublicKeysReader(reader).
			WithCacheTTL(time.Minute * 10).
			WithCacheRefreshInterval(time.Second * 30).
			WithAllowUntrustedImages(false).
			Build()
		Expect(err).ToNot(HaveOccurred())
		handler = h
	})

	DescribeTable(
		"Resource handling",
		func(request admission.Request, allowed bool, errMsg string) {
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(Equal(allowed))
			if !allowed {
				Expect(response.AdmissionResponse.Result.Message).To(Or(BeEmpty(), ContainSubstring(errMsg)))
				Expect(response.AdmissionResponse.Result.Code).To(Satisfy(isHTTPError))
			}
		},
		Entry("Allow apps/v1.deployments", admissionRequestBuilder{gvk: deploymentGVK}.Build(), true, ""),
		Entry("Allow status subResource requests on pods", admissionRequestBuilder{gvk: podGVK, subResource: "status"}.Build(), true, ""),
		Entry("Allow update status subResource requests on pods with invalid image", admissionRequestBuilder{gvk: podGVK, subResource: "status", operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build(), true, ""),
		Entry("Allow delete operation on pods", admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Delete}.Build(), true, ""),
		Entry("Allow connect operation on pods", admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Connect}.Build(), true, ""),
		Entry("Disallow undecodable pod", admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Create, object: invalidPod}.Build(), false, `no kind "InvalidKind" is registered for version`),
		Entry("Disallow pod with invalid image", admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build(), false, "could not parse reference"),
		Entry("Disallow pod with invalid image via ephemeralcontainers subResource request", admissionRequestBuilder{gvk: podGVK, subResource: "ephemeralcontainers", operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build(), false, "could not parse reference"),
	)

	It("Should properly verify image signature", func() {
		request := admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Create, object: pod}.Build()
		response := handler.Handle(ctx, request)
		Expect(response.Allowed).To(BeTrue())
		Expect(response.Result.Code).To(BeEquivalentTo(http.StatusOK))
	})

	It("Should allow untrusted images", func() {
		mgr.EXPECT().GetAPIReader().Return(apiReader)
		mgr.EXPECT().GetScheme().Return(scheme)
		reader := strings.NewReader(cosignPublicKey)

		allowUntrustedHandler, err := verifysignature.
			NewHandleBuilder().
			WithManager(mgr).
			WithLogger(logger.WithName("test-cosign-untrusted-handler")).
			WithCosignPublicKeysReader(reader).
			WithCacheTTL(time.Minute * 10).
			WithCacheRefreshInterval(time.Second * 30).
			WithAllowUntrustedImages(true).
			Build()
		Expect(err).ToNot(HaveOccurred())

		req := admissionRequestBuilder{
			gvk:       podGVK,
			operation: admissionv1.Update,
			object:    podWithImage(pod, "alpine@sha256:11e21d7b981a59554b3f822c49f6e9f57b6068bb74f49c4cd5cc4c663c7e5160"),
		}.Build()
		ar := allowUntrustedHandler.Handle(ctx, req)
		Expect(ar.Allowed).To(BeTrue())
		Expect(ar.Result.Code).To(BeEquivalentTo(http.StatusOK))
		Expect(ar.Warnings).To(ContainElement(ContainSubstring("Failed to admit pod with error")))
		Expect(ar.Warnings).To(ContainElement(ContainSubstring("Forbidden: no valid signature found for image")))
		Expect(ar.Result.Message).To(ContainSubstring("untrusted images are allowed"))

		ar = handler.Handle(ctx, req)
		Expect(ar.Allowed).To(BeFalse())
		Expect(ar.Result.Code).To(Satisfy(isHTTPError))
		Expect(ar.Result.Message).To(ContainSubstring("Forbidden: no valid signature found for image"))
	})
})

func isHTTPError(code int32) bool {
	return code >= 400
}

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

type admissionRequestBuilder struct {
	gvk         metav1.GroupVersionKind
	subResource string
	operation   admissionv1.Operation
	object      runtime.Object
}

func (a admissionRequestBuilder) Build() admission.Request {
	request := admission.Request{}

	request.AdmissionRequest.Kind = a.gvk
	request.AdmissionRequest.SubResource = a.subResource
	request.AdmissionRequest.Operation = a.operation
	request.AdmissionRequest.Object = runtime.RawExtension{Raw: encode(a.object)}

	return request
}

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	lakomconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
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
	deploymentGVK           = metav1.GroupVersionKind{Group: "apps", Kind: "Deployment", Version: "v1"}
	podGVK                  = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controllerDeploymentGVK = metav1.GroupVersionKind{Group: "core.gardener.cloud", Kind: "ControllerDeployment", Version: "v1"}
	gardenletGVK            = metav1.GroupVersionKind{Group: "seedmanagement.gardener.cloud", Kind: "Gardenlet", Version: "v1alpha1"}
	extensionGVK            = metav1.GroupVersionKind{Group: "extensions.operator.gardener.cloud", Kind: "Extension", Version: "v1alpha1"}
)

var _ = Describe("Admission Handler", func() {
	var (
		ctx          = context.Background()
		logger       logr.Logger
		handler      admission.Handler
		cosignConfig lakomconfig.Config
		pod          = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "pod-namespace",
				Name:      "pod-name",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "container",
					Image: signedImageFullRef,
				}},
			},
		}
		cd = &gardencorev1.ControllerDeployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "cd-namespace",
				Name:      "cd-name",
			},
			Helm: &gardencorev1.HelmControllerDeployment{
				OCIRepository: &gardencorev1.OCIRepository{
					Ref: &signedImageFullRef,
				},
			},
		}
		gardenlet = &seedmanagementv1alpha1.Gardenlet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "gardenlet-namespace",
				Name:      "gardenlet-name",
			},
			Spec: seedmanagementv1alpha1.GardenletSpec{
				Deployment: seedmanagementv1alpha1.GardenletSelfDeployment{
					Helm: seedmanagementv1alpha1.GardenletHelm{
						OCIRepository: gardencorev1.OCIRepository{
							Ref: &signedImageFullRef,
						},
					},
				},
			},
		}
		extension = &operatorv1alpha1.Extension{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "extension-namespace",
				Name:      "extension-name",
			},
			Spec: operatorv1alpha1.ExtensionSpec{
				Deployment: &operatorv1alpha1.Deployment{
					ExtensionDeployment: &operatorv1alpha1.ExtensionDeploymentSpec{
						DeploymentSpec: operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref: &signedImageFullRef,
								},
							},
						},
					},
					AdmissionDeployment: &operatorv1alpha1.AdmissionDeploymentSpec{
						RuntimeCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref: &signedImageFullRef,
								},
							},
						},
						VirtualCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref: &signedImageFullRef,
								},
							},
						},
					},
				},
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
		cosignConfig = lakomconfig.Config{
			PublicKeys: []lakomconfig.Key{
				{
					Name: "test",
					Key:  publicKey,
				},
			},
		}
		h, err := verifysignature.
			NewHandleBuilder().
			WithManager(mgr).
			WithLogger(logger.WithName("test-cosign-signature-verifier")).
			WithLakomConfig(cosignConfig).
			WithCacheTTL(time.Minute * 10).
			WithCacheRefreshInterval(time.Second * 30).
			WithAllowUntrustedImages(false).
			Build()
		Expect(err).ToNot(HaveOccurred())
		handler = h

		pod.Spec.Containers[0].Image = signedImageFullRef
		cd.Helm.OCIRepository.Ref = &signedImageFullRef
		gardenlet.Spec.Deployment.Helm.OCIRepository.Ref = &signedImageFullRef
		extension.Spec.Deployment.ExtensionDeployment.DeploymentSpec.Helm.OCIRepository.Ref = &signedImageFullRef
		extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.Ref = &signedImageFullRef
		extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.Ref = &signedImageFullRef
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
		Entry("Disallow controller deployment with invalid artifact", admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeploymentWithChart(cd, "invalid-artifact@sha256:123")}.Build(), false, "could not parse reference"),
		Entry("Disallow gardenlet with invalid artifact", admissionRequestBuilder{gvk: gardenletGVK, operation: admissionv1.Create, object: gardenletWithChart(gardenlet, "invalid-artifact@sha256:123")}.Build(), false, "could not parse reference"),
		Entry("Disallow extension with invalid artifact", admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extensionWithChart(extension, "invalid-artifact@sha256:123")}.Build(), false, "could not parse reference"),
	)

	// Use a closure for building the request to capture a ref of the
	// the object (pod, controllerdeployment, ...) instead of the value.
	// Ref: https://github.com/onsi/ginkgo/issues/378
	DescribeTable(
		"Proper verification of artifacts",
		func(requestBuilder func() admission.Request, allowed bool) {
			request := requestBuilder()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(Equal(allowed))
			Expect(response.Result.Code).To(BeEquivalentTo(http.StatusOK))
		},
		Entry("Should properly verify pod image signature", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Create, object: pod}.Build()
		}, true),
		Entry("Should properly verify controllerdeployment artifact signature", func() admission.Request {
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: cd}.Build()
		}, true),
		Entry("Should properly verify gardenlet artifact signature", func() admission.Request {
			return admissionRequestBuilder{gvk: gardenletGVK, operation: admissionv1.Create, object: gardenlet}.Build()
		}, true),
		Entry("Should properly verify extension artifact signature", func() admission.Request {
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}, true),
	)

	It("Should allow untrusted artifacts", func() {
		mgr.EXPECT().GetAPIReader().Return(apiReader)
		mgr.EXPECT().GetScheme().Return(scheme)

		allowUntrustedHandler, err := verifysignature.
			NewHandleBuilder().
			WithManager(mgr).
			WithLogger(logger.WithName("test-cosign-untrusted-handler")).
			WithLakomConfig(cosignConfig).
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
		Expect(ar.Warnings).To(ContainElement(ContainSubstring("Failed to admit resource with error")))
		Expect(ar.Warnings).To(ContainElement(ContainSubstring("Forbidden: no valid signature found for artifact")))
		Expect(ar.Result.Message).To(ContainSubstring("untrusted artifacts are allowed"))

		ar = handler.Handle(ctx, req)
		Expect(ar.Allowed).To(BeFalse())
		Expect(ar.Result.Code).To(Satisfy(isHTTPError))
		Expect(ar.Result.Message).To(ContainSubstring("Forbidden: no valid signature found for artifact"))
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

func controllerDeploymentWithChart(controllerDeployment *gardencorev1.ControllerDeployment, artifact string) *gardencorev1.ControllerDeployment {
	cd := controllerDeployment.DeepCopy()
	cd.Helm.OCIRepository.Ref = &artifact
	return cd
}

func gardenletWithChart(gardenlet *seedmanagementv1alpha1.Gardenlet, artifact string) *seedmanagementv1alpha1.Gardenlet {
	g := gardenlet.DeepCopy()
	g.Spec.Deployment.Helm.OCIRepository.Ref = &artifact
	return g
}

func extensionWithChart(extension *operatorv1alpha1.Extension, artifact string) *operatorv1alpha1.Extension {
	e := extension.DeepCopy()
	e.Spec.Deployment.ExtensionDeployment.DeploymentSpec.Helm.OCIRepository.Ref = &artifact
	e.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.Ref = &artifact
	e.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.Ref = &artifact
	return e
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

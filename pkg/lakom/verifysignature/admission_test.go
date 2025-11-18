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
	"github.com/google/go-containerregistry/pkg/name"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	deploymentGVK           = metav1.GroupVersionKind{Group: "apps", Kind: "Deployment", Version: "v1"}
	podGVK                  = metav1.GroupVersionKind{Group: "", Kind: "Pod", Version: "v1"}
	controllerDeploymentGVK = metav1.GroupVersionKind{Group: "core.gardener.cloud", Kind: "ControllerDeployment", Version: "v1"}
	gardenletGVK            = metav1.GroupVersionKind{Group: "seedmanagement.gardener.cloud", Kind: "Gardenlet", Version: "v1alpha1"}
	extensionGVK            = metav1.GroupVersionKind{Group: "operator.gardener.cloud", Kind: "Extension", Version: "v1alpha1"}
)

var _ = Describe("Admission Handler", func() {
	var (
		ctx          context.Context
		logger       logr.Logger
		handler      admission.Handler
		cosignConfig lakomconfig.Config

		imagePullSecretName string

		signedImageRepository string
		signedImageDigest     string

		pod                  *corev1.Pod
		controllerDeployment *gardencorev1.ControllerDeployment
		gardenlet            *seedmanagementv1alpha1.Gardenlet
		extension            *operatorv1alpha1.Extension
		invalidPod           runtime.Object
	)

	BeforeEach(func() {
		const gardenNamespace = "garden"
		ctx = context.Background()
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

		imagePullSecretName = "image-pull-secret" //#nosec G101 -- this is just a name of non-existing test resource
		imagePullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gardenNamespace,
				Name:      imagePullSecretName,
			},
		}

		apiReader.EXPECT().
			Get(gomock.Any(), client.ObjectKey{Namespace: gardenNamespace, Name: imagePullSecretName}, gomock.AssignableToTypeOf(&corev1.Secret{})).
			AnyTimes().
			SetArg(2, *imagePullSecret)

		ref, err := name.NewDigest(signedImageFullRef)
		Expect(err).ToNot(HaveOccurred())
		signedImageRepository = ref.Context().Name()
		signedImageDigest = ref.DigestStr()

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

		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gardenNamespace,
				Name:      "pod-name",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "container",
					Image: signedImageFullRef,
				}},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: imagePullSecretName}},
			},
		}
		controllerDeployment = &gardencorev1.ControllerDeployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "cd-namespace",
				Name:      "cd-name",
			},
			Helm: &gardencorev1.HelmControllerDeployment{
				OCIRepository: &gardencorev1.OCIRepository{
					Ref:           &signedImageFullRef,
					PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
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
							Ref:           &signedImageFullRef,
							PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
						},
					},
					GardenletDeployment: seedmanagementv1alpha1.GardenletDeployment{
						Image: &seedmanagementv1alpha1.Image{
							Repository: &signedImageRepository,
							Tag:        &signedImageDigest,
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
									Ref:           &signedImageFullRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
								},
							},
						},
					},
					AdmissionDeployment: &operatorv1alpha1.AdmissionDeploymentSpec{
						RuntimeCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref:           &signedImageFullRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
								},
							},
						},
						VirtualCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref:           &signedImageFullRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
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
	})

	DescribeTable("Resource handling",
		func(requestBuilder func() admission.Request, allowed bool, errMsg string) {
			request := requestBuilder()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(Equal(allowed))
			if !allowed {
				Expect(response.AdmissionResponse.Result.Message).To(Or(BeEmpty(), ContainSubstring(errMsg)))
				Expect(response.AdmissionResponse.Result.Code).To(Satisfy(isHTTPError))
			}
		},
		Entry("Allow apps/v1.deployments", func() admission.Request {
			return admissionRequestBuilder{gvk: deploymentGVK}.Build()
		}, true, ""),
		Entry("Allow status subResource requests on pods", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, subResource: "status"}.Build()
		}, true, ""),
		Entry("Allow update status subResource requests on pods with invalid image", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, subResource: "status", operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build()
		}, true, ""),
		Entry("Allow delete operation on pods", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Delete}.Build()
		}, true, ""),
		Entry("Allow connect operation on pods", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Connect}.Build()
		}, true, ""),
		Entry("Disallow undecodable pod", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Create, object: invalidPod}.Build()
		}, false, `no kind "InvalidKind" is registered for version`),
		Entry("Disallow pod with invalid image", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build()
		}, false, "could not parse reference"),
		Entry("Disallow pod with invalid image via ephemeralcontainers subResource request", func() admission.Request {
			return admissionRequestBuilder{gvk: podGVK, subResource: "ephemeralcontainers", operation: admissionv1.Update, object: podWithImage(pod, "invalid-image@sha256:123")}.Build()
		}, false, "could not parse reference"),
		Entry("Disallow controller deployment with invalid artifact", func() admission.Request {
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeploymentWithChart(controllerDeployment, "invalid-artifact@sha256:123")}.Build()
		}, false, "could not parse reference"),
		Entry("Disallow gardenlet with invalid artifact", func() admission.Request {
			return admissionRequestBuilder{gvk: gardenletGVK, operation: admissionv1.Create, object: gardenletWithChart(gardenlet, "invalid-artifact@sha256:123")}.Build()
		}, false, "could not parse reference"),
		Entry("Disallow extension with invalid artifact", func() admission.Request {
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extensionWithChart(extension, "invalid-artifact@sha256:123")}.Build()
		}, false, "could not parse reference"),
	)

	// Use a closure for building the request to capture a ref of the
	// the object (pod, controllerdeployment, ...) instead of the value.
	// Ref: https://github.com/onsi/ginkgo/issues/378
	DescribeTable("Proper verification of artifacts",
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
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeployment}.Build()
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

	DescribeTable("Should succeed when optional fields are missing",
		func(requestBuilder func() admission.Request) {
			request := requestBuilder()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(BeTrue())
			Expect(response.Result).ToNot(BeNil())
			Expect(response.Result.Code).To(BeEquivalentTo(http.StatusOK))
		},
		Entry("gardenlet.spec.deployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			gardenlet.Spec.Deployment.Helm.OCIRepository.PullSecretRef = nil
			return admissionRequestBuilder{gvk: gardenletGVK, operation: admissionv1.Create, object: gardenlet}.Build()
		}),
		Entry("gardenlet.spec.deployment.image is nil", func() admission.Request {
			gardenlet.Spec.Deployment.Image = nil
			return admissionRequestBuilder{gvk: gardenletGVK, operation: admissionv1.Create, object: gardenlet}.Build()
		}),
		Entry("controllerDeployment.helm is nil", func() admission.Request {
			controllerDeployment.Helm = nil
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeployment}.Build()
		}),
		Entry("controllerDeployment.helm.ociRepository is nil", func() admission.Request {
			controllerDeployment.Helm.OCIRepository = nil
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeployment}.Build()
		}),
		Entry("controllerDeployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			controllerDeployment.Helm.OCIRepository.PullSecretRef = nil
			return admissionRequestBuilder{gvk: controllerDeploymentGVK, operation: admissionv1.Create, object: controllerDeployment}.Build()
		}),
		Entry("extension.spec.deployment is nil", func() admission.Request {
			extension.Spec.Deployment = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.PullSecretRef = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.PullSecretRef = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.extensionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.PullSecretRef = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
		Entry("extension.spec.deployment.extensionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment = nil
			return admissionRequestBuilder{gvk: extensionGVK, operation: admissionv1.Create, object: extension}.Build()
		}),
	)
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
	e.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.Ref = &artifact
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

	request.Kind = a.gvk
	request.SubResource = a.subResource
	request.Operation = a.operation
	request.Object = runtime.RawExtension{Raw: encode(a.object)}

	return request
}

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

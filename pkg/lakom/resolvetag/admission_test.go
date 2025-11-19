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

	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
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
		ctx     context.Context
		logger  logr.Logger
		handler admission.Handler

		signedImageRepository string
		signedImageDigest     string

		imagePullSecretName     string
		pod                     *corev1.Pod
		podPaths                []string
		podExpectedPatchesCount int

		controllerDeployment   *gardencorev1.ControllerDeployment
		cdPaths                []string
		cdExpectedPatchesCount int

		gardenlet                     *seedmanagementv1alpha1.Gardenlet
		gardenletPaths                []string
		gardenletExpectedPatchesCount int

		extension                     *operatorv1alpha1.Extension
		extensionPaths                []string
		extensionExpectedPatchesCount int

		invalidPod runtime.Object
	)

	BeforeEach(func() {
		const gardenNamespace = "garden"
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mgr = mockmanager.NewMockManager(ctrl)
		apiReader = mockclient.NewMockReader(ctrl)

		mgr.EXPECT().GetAPIReader().Return(apiReader)
		mgr.EXPECT().GetScheme().Return(scheme)

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

		ref, err := name.NewDigest(signedImageDigestRef)
		Expect(err).ToNot(HaveOccurred())
		signedImageRepository = ref.Context().Name()
		signedImageDigest = ref.DigestStr()

		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gardenNamespace,
				Name:      "pod-name",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "container",
					Image: signedImageTagRef,
				}},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: imagePullSecretName}},
			},
		}
		podPaths = []string{"/spec/containers/0/image"}
		podExpectedPatchesCount = 1

		controllerDeployment = &gardencorev1.ControllerDeployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "cd-namespace",
				Name:      "cd-name",
			},
			Helm: &gardencorev1.HelmControllerDeployment{
				OCIRepository: &gardencorev1.OCIRepository{
					Ref:           &signedImageTagRef,
					PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
				},
			},
		}
		cdPaths = []string{"/helm/ociRepository/ref"}
		cdExpectedPatchesCount = 1

		gardenlet = &seedmanagementv1alpha1.Gardenlet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "gardenlet-namespace",
				Name:      "gardenlet-name",
			},
			Spec: seedmanagementv1alpha1.GardenletSpec{
				Deployment: seedmanagementv1alpha1.GardenletSelfDeployment{
					Helm: seedmanagementv1alpha1.GardenletHelm{
						OCIRepository: gardencorev1.OCIRepository{
							Ref:           &signedImageTagRef,
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
		gardenletPaths = []string{"/spec/deployment/helm/ociRepository/ref"}
		gardenletExpectedPatchesCount = 1

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
									Ref:           &signedImageTagRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
								},
							},
						},
					},
					AdmissionDeployment: &operatorv1alpha1.AdmissionDeploymentSpec{
						RuntimeCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref:           &signedImageTagRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
								},
							},
						},
						VirtualCluster: &operatorv1alpha1.DeploymentSpec{
							Helm: &operatorv1alpha1.ExtensionHelm{
								OCIRepository: &gardencorev1.OCIRepository{
									Ref:           &signedImageTagRef,
									PullSecretRef: &corev1.LocalObjectReference{Name: imagePullSecretName},
								},
							},
						},
					},
				},
			},
		}
		extensionPaths = []string{
			"/spec/deployment/extension/helm/ociRepository/ref",
			"/spec/deployment/admission/runtimeCluster/helm/ociRepository/ref",
			"/spec/deployment/admission/virtualCluster/helm/ociRepository/ref",
		}
		extensionExpectedPatchesCount = 3

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
				Expect(response.AdmissionResponse.Result.Message).To(ContainSubstring(errMsg))
				Expect(response.AdmissionResponse.Result.Code).To(BeEquivalentTo(http.StatusInternalServerError))
			}
		},
		Entry("Allow apps/v1.deployments", func() admission.Request {
			return arb{}.withKind(deploymentGVK).withOperation(admissionv1.Create).Build()
		}, true, ""),
		Entry("Allow status subResource requests on pods", func() admission.Request {
			return arb{}.withKind(podGVK).withSubResource("status").Build()
		}, true, ""),
		Entry("Allow update status subResource requests on pods with invalid image", func() admission.Request {
			return arb{}.withKind(podGVK).withSubResource("status").withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build()
		}, true, ""),
		Entry("Allow delete operation on pods", func() admission.Request {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Delete).Build()
		}, true, ""),
		Entry("Allow connect operation on pods", func() admission.Request {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Connect).Build()
		}, true, ""),
		Entry("Disallow undecodable pod", func() admission.Request {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Create).withObject(invalidPod).Build()
		}, false, `no kind "InvalidKind" is registered for version`),
		Entry("Disallow pod with invalid image", func() admission.Request {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build()
		}, false, "could not parse reference"),
		Entry("Disallow pod with invalid image via ephemeralcontainers subResource request", func() admission.Request {
			return arb{}.withKind(podGVK).withSubResource("ephemeralcontainers").withOperation(admissionv1.Update).withObject(podWithImage(pod, "invalid-image@sha256:123")).Build()
		}, false, "could not parse reference"),
	)

	// Use a closure for building the request to capture a ref of the
	// the object (pod, controllerdeployment, ...) instead of the value.
	// Ref: https://github.com/onsi/ginkgo/issues/378
	DescribeTable("Resolve tags to digests",
		func(testParams func() (admission.Request, string, int, []string)) {
			request, expectedImage, expectedPatchesCount, expectedPaths := testParams()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(BeTrue())
			Expect(response.Patches).To(HaveLen(expectedPatchesCount))
			for _, patch := range response.Patches {
				Expect(patch.Operation).To(Equal("replace"))
				Expect(patch.Value).To(Equal(expectedImage))
				Expect(expectedPaths).To(ContainElement(patch.Path))
			}
		},
		Entry("Resolve tag to digest for pod", func() (admission.Request, string, int, []string) {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Create).withObject(pod).Build(), signedImageDigestRef, podExpectedPatchesCount, podPaths
		}),
		Entry("Resolve tag to digest for controllerdeployment", func() (admission.Request, string, int, []string) {
			return arb{}.withKind(controllerDeploymentGVK).withOperation(admissionv1.Create).withObject(controllerDeployment).Build(), signedImageDigestRef, cdExpectedPatchesCount, cdPaths
		}),
		Entry("Resolve tag to digest for gardenlet helm chart image", func() (admission.Request, string, int, []string) {
			return arb{}.withKind(gardenletGVK).withOperation(admissionv1.Create).withObject(gardenlet).Build(), signedImageDigestRef, gardenletExpectedPatchesCount, gardenletPaths
		}),
		Entry("Resolve tag to digest for extension", func() (admission.Request, string, int, []string) {
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build(), signedImageDigestRef, extensionExpectedPatchesCount, extensionPaths
		}),
	)

	It("Should resolve tag to digest for gardenlet container image", func() {
		tag := signedImageTag
		gardenlet.Spec.Deployment.GardenletDeployment = seedmanagementv1alpha1.GardenletDeployment{
			Image: &seedmanagementv1alpha1.Image{
				Repository: &signedImageRepository,
				Tag:        &tag,
			},
		}
		gardenlet.Spec.Deployment.Helm.OCIRepository.Ref = &signedImageDigestRef
		request := arb{}.withKind(gardenletGVK).withOperation(admissionv1.Create).withObject(gardenlet).Build()

		response := handler.Handle(ctx, request)
		Expect(response.Allowed).To(BeTrue())
		Expect(response.Patches).To(HaveLen(1))
		Expect(response.Patches).To(HaveExactElements(
			MatchFields(IgnoreExtras, Fields{
				"Operation": Equal("replace"),
				"Path":      Equal("/spec/deployment/image/tag"),
				"Value":     Equal(signedImageDigest),
			}),
		))
	})

	DescribeTable("Do not patch resource already using digests",
		func(requestBuilder func() admission.Request) {
			request := requestBuilder()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(BeTrue())
			Expect(response.Patches).To(BeEmpty())
		},
		Entry("pod", func() admission.Request {
			return arb{}.withKind(podGVK).withOperation(admissionv1.Create).withObject(podWithImage(pod, signedImageDigestRef)).Build()
		}),
		Entry("controllerdeployment", func() admission.Request {
			controllerDeployment.Helm.OCIRepository.Ref = &signedImageDigestRef
			return arb{}.withKind(controllerDeploymentGVK).withOperation(admissionv1.Create).withObject(controllerDeployment).Build()
		}),
		Entry("gardenlet helm chart image", func() admission.Request {
			gardenlet.Spec.Deployment.Helm.OCIRepository.Ref = &signedImageDigestRef
			gardenlet.Spec.Deployment.Image = &seedmanagementv1alpha1.Image{
				Repository: &signedImageRepository,
				Tag:        &signedImageDigest,
			}
			return arb{}.withKind(gardenletGVK).withOperation(admissionv1.Create).withObject(gardenlet).Build()
		}),
		Entry("extension", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.Ref = &signedImageDigestRef
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.Ref = &signedImageDigestRef
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.Ref = &signedImageDigestRef
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
	)

	DescribeTable("Should succeed when optional fields are missing",
		func(requestBuilder func() admission.Request) {
			request := requestBuilder()
			response := handler.Handle(ctx, request)
			Expect(response.Allowed).To(BeTrue())
			Expect(response.Result).To(BeNil())
		},
		Entry("gardenlet.spec.deployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			gardenlet.Spec.Deployment.Helm.OCIRepository.PullSecretRef = nil
			return arb{}.withKind(gardenletGVK).withOperation(admissionv1.Create).withObject(gardenlet).Build()
		}),
		Entry("gardenlet.spec.deployment.image is nil", func() admission.Request {
			gardenlet.Spec.Deployment.Image = nil
			return arb{}.withKind(gardenletGVK).withOperation(admissionv1.Create).withObject(gardenlet).Build()
		}),
		Entry("controllerDeployment.helm is nil", func() admission.Request {
			controllerDeployment.Helm = nil
			return arb{}.withKind(controllerDeploymentGVK).withOperation(admissionv1.Create).withObject(controllerDeployment).Build()
		}),
		Entry("controllerDeployment.helm.ociRepository is nil", func() admission.Request {
			controllerDeployment.Helm.OCIRepository = nil
			return arb{}.withKind(controllerDeploymentGVK).withOperation(admissionv1.Create).withObject(controllerDeployment).Build()
		}),
		Entry("controllerDeployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			controllerDeployment.Helm.OCIRepository.PullSecretRef = nil
			return arb{}.withKind(controllerDeploymentGVK).withOperation(admissionv1.Create).withObject(controllerDeployment).Build()
		}),
		Entry("extension.spec.deployment is nil", func() admission.Request {
			extension.Spec.Deployment = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.runtimeCluster.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.RuntimeCluster.Helm.OCIRepository.PullSecretRef = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.admissionDeployment.virtualCluster.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.AdmissionDeployment.VirtualCluster.Helm.OCIRepository.PullSecretRef = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.extensionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm.ociRepository is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.ExtensionDeployment.helm.ociRepository.pullSecretRef is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment.Helm.OCIRepository.PullSecretRef = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
		Entry("extension.spec.deployment.extensionDeployment is nil", func() admission.Request {
			extension.Spec.Deployment.ExtensionDeployment = nil
			return arb{}.withKind(extensionGVK).withOperation(admissionv1.Create).withObject(extension).Build()
		}),
	)
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

	request.Kind = arb.gvk
	request.SubResource = arb.subResource
	request.Operation = arb.operation
	request.Object = arb.object

	return request
}

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

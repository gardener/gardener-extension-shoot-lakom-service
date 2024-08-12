package lakom_test

import (
	"context"
	"encoding/json"
	"testing"

	lakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/admission/validator/lakom"
	apilakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	v1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestLakom(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Lakom Suite")
}

var _ = Describe("Shoot validator", func() {
	var (
		ctx = context.Background()

		shootValidator extensionswebhook.Validator
		ctrl           *gomock.Controller
		apiReader      *mockclient.MockReader

		shoot *core.Shoot
	)

	Describe("#Validate", func() {
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			utilruntime.Must(apilakom.AddToScheme(scheme))
			utilruntime.Must(v1alpha1.AddToScheme(scheme))

			decoder := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
			apiReader = mockclient.NewMockReader(ctrl)
			ctrl = gomock.NewController(GinkgoT())

			shootValidator = lakom.NewShootValidator(apiReader, decoder)

			shoot = &core.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "garden-tst",
					Name:      "tst",
				},
				Spec: core.ShootSpec{
					Extensions: []core.Extension{
						{
							Type: "shoot-lakom-service",
							ProviderConfig: &runtime.RawExtension{
								Raw: encode(&v1alpha1.LakomConfig{
									TypeMeta: metav1.TypeMeta{
										APIVersion: v1alpha1.SchemeGroupVersion.String(),
										Kind:       "LakomConfig",
									},
									Scope: apilakom.Cluster,
								}),
							},
						},
					},
				},
			}
		})

		It("should return err when new is not a Shoot", func() {
			err := shootValidator.Validate(ctx, &corev1.Pod{}, nil)

			Expect(err).To(HaveOccurred())
		})

		It("should do nothing when the Shoot does no specify a shoot-lakom-service extension", func() {
			shoot.Spec.Extensions[0].Type = "foo"

			Expect(shootValidator.Validate(ctx, shoot, nil)).To(Succeed())
		})

		It("should return err when shoot-lakom-service providerConfig cannot be decoded", func() {
			shoot.Spec.Extensions[0].ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"bar": "baz"}`),
			}

			err := shootValidator.Validate(ctx, shoot, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should succeed for valid Shoot", func() {
			Expect(shootValidator.Validate(ctx, shoot, nil)).To(Succeed())
		})

		It("should fail if the given scope is not recognized", func() {
			extension := &runtime.RawExtension{
				Raw: encode(&v1alpha1.LakomConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: v1alpha1.SchemeGroupVersion.String(),
						Kind:       "LakomConfig",
					},
					Scope: "invalid",
				}),
			}

			shoot.Spec.Extensions[0].ProviderConfig = extension

			err := shootValidator.Validate(ctx, shoot, nil)
			Expect(err).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("spec.extensions[0].providerConfig.scope"),
			}))))
		})

	})
})

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

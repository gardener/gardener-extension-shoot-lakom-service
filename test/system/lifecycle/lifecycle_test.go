// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

/**
	TODO(vpnachev): Update the tests to fit lakom case
	Overview
		- Tests the lifecycle controller for the shoot-lakom-service extension.
	Prerequisites
		- A Shoot exists and the lakom extension is available for the seed cluster.
**/

package lifecycle_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	framework.RegisterShootFrameworkFlags()
}

const (
	timeout = 30 * time.Minute
)

var _ = Describe("Shoot lakom service testing", func() {
	f := framework.NewShootFramework(nil)

	var initialExtensionConfig []gardencorev1beta1.Extension

	BeforeEach(func() {
		initialExtensionConfig = f.Shoot.Spec.Extensions
	})

	AfterEach(func() {
		// Revert to initial extension configuration
		Expect(f.UpdateShoot(context.Background(), func(shoot *gardencorev1beta1.Shoot) error {
			shoot.Spec.Extensions = initialExtensionConfig
			return nil
		})).To(Succeed())
	})

	f.Serial().Beta().CIt("Should perform the common case scenario without any errors", func(ctx context.Context) {
		err := f.UpdateShoot(ctx, ensureLakomServiceIsEnabled)
		Expect(err).ToNot(HaveOccurred())

		lakomDeployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationName,
				Namespace: f.ShootSeedNamespace(),
			},
		}

		// Verify that the lakom deployment exists and is deployed with the correct number of replicas
		err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(lakomDeployment), lakomDeployment)
		Expect(err).ToNot(HaveOccurred())
		one := int32(1)
		Expect(*lakomDeployment.Spec.Replicas).To(BeNumerically(">=", one))
		Expect(lakomDeployment.Status.ReadyReplicas).To(BeNumerically(">=", one))

		lakonConfig, err := getLakomConfig(ctx, f.SeedClient.RESTClient())
		if err == nil {
			jwksURL, err := url.Parse(lakonConfig.JWKSURL)
			Expect(err).ToNot(HaveOccurred())

			jwks, err := getJWKS(ctx, f.SeedClient.RESTClient(), jwksURL.Path)
			Expect(err).ToNot(HaveOccurred())
			clientId := "some-custom-client-id"
			oidcAPIVersion := "authentication.gardener.cloud/v1alpha1"
			oidcKind := "OpenIDConnect"

			// Deploy lakom resource
			lakom := &unstructured.Unstructured{}
			lakom.Object = map[string]interface{}{
				"apiVersion": oidcAPIVersion,
				"kind":       oidcKind,
				"metadata": map[string]interface{}{
					"name": "custom",
				},
				"spec": map[string]interface{}{
					"issuerURL":      lakonConfig.Issuer,
					"clientID":       clientId,
					"usernameClaim":  "sub",
					"usernamePrefix": "custom-prefix:",
					"jwks": map[string]interface{}{
						"keys": jwks,
					},
				},
			}
			err = f.ShootClient.Client().Create(ctx, lakom, &client.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			lakom = &unstructured.Unstructured{}
			lakom.SetAPIVersion(oidcAPIVersion)
			lakom.SetKind(oidcKind)
			lakom.SetName("custom")
			err = f.ShootClient.Client().Get(ctx, client.ObjectKeyFromObject(lakom), lakom)
			Expect(err).ToNot(HaveOccurred())

			// Conversion should be safe
			spec := lakom.Object["spec"].(map[string]interface{})
			Expect(spec["clientID"]).To(Equal(clientId))
			Expect(spec["issuerURL"]).To(Equal(lakonConfig.Issuer))

			// Get token from seed
			var ttl int64 = 1800
			tokenReq, err := f.SeedClient.Kubernetes().CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{clientId},
					ExpirationSeconds: &ttl,
				},
			}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			expectedStatus := status{
				Status:  "Failure",
				Message: `forbidden: User "custom-prefix:system:serviceaccount:default:default" cannot get path "/"`,
				Reason:  "Forbidden",
				Code:    403,
			}

			// Expect API calls to be authenticated
			Eventually(func() status {
				statusError, err := requestAPIServer(ctx, f.ShootClient.RESTConfig().CAData, f.ShootClient.RESTConfig().Host, tokenReq.Status.Token)
				Expect(err).ToNot(HaveOccurred())

				return status{
					Code:    int(statusError.Code),
					Message: statusError.Message,
					Reason:  string(statusError.Reason),
					Status:  statusError.Status,
				}
			}, time.Second*20, time.Second).Should(Equal(expectedStatus))

			// Delete the lakom resource
			err = f.ShootClient.Client().Delete(ctx, lakom, &client.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Expect API calls to be unauthorized
			expectedStatus.Code = 401
			expectedStatus.Message = "Unauthorized"
			expectedStatus.Reason = string(metav1.StatusReasonUnauthorized)
			Eventually(func() status {
				statusError, err := requestAPIServer(ctx, f.ShootClient.RESTConfig().CAData, f.ShootClient.RESTConfig().Host, tokenReq.Status.Token)
				Expect(err).ToNot(HaveOccurred())

				return status{
					Code:    int(statusError.Code),
					Message: statusError.Message,
					Reason:  string(statusError.Reason),
					Status:  statusError.Status,
				}
			}, time.Second*20, time.Second).Should(Equal(expectedStatus))
		} else {
			f.Logger.Info(fmt.Sprintf("Cannot register the seed as identity provider. Error: %s. The verification of lakom provider registration was skipped. Continuing with test execution...", err.Error()))
		}

		// Ensure that the Lakom service is disabled in order to verify the deletion process
		Expect(f.UpdateShoot(ctx, ensureLakomServiceIsDisabled)).To(Succeed())

		// Ensure that lakom deployment is deleted
		err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(lakomDeployment), lakomDeployment)
		Expect(err).To(HaveOccurred())
		Expect(err).To(BeNotFoundError())

		// Ensure that manually deployed secrets are deleted
		for _, name := range []string{
			gardenerutils.SecretNamePrefixShootAccess + constants.ApplicationName,
			constants.WebhookTLSSecretName,
		} {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: f.ShootSeedNamespace(),
				},
			}
			err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(secret), secret)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeNotFoundError())
		}
	}, timeout)
})

func ensureLakomServiceIsEnabled(shoot *gardencorev1beta1.Shoot) error {
	for i, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType {
			if e.Disabled != nil && *e.Disabled == true {
				shoot.Spec.Extensions[i].Disabled = ptr.To[bool](false)
			}
			return nil
		}
	}

	shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
		Type:     constants.ExtensionType,
		Disabled: ptr.To[bool](false),
	})
	return nil
}

func ensureLakomServiceIsDisabled(shoot *gardencorev1beta1.Shoot) error {
	for i, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType {
			shoot.Spec.Extensions[i].Disabled = ptr.To[bool](true)
			return nil
		}
	}
	return nil
}

type lakomConfig struct {
	Issuer                 string   `json:"issuer,omitempty"`
	JWKSURL                string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`
	SigningAlgsSupported   []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

func getLakomConfig(ctx context.Context, client rest.Interface) (*lakomConfig, error) {
	oidReq := client.Get()
	oidReq.RequestURI("/.well-known/openid-configuration")
	respBytes, err := oidReq.DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	lakomConfig := &lakomConfig{}
	err = json.Unmarshal(respBytes, lakomConfig)
	if err != nil {
		return nil, err
	}
	return lakomConfig, nil
}

func getJWKS(ctx context.Context, client rest.Interface, relativeUri string) ([]byte, error) {
	jwksReq := client.Get()
	jwksReq.RequestURI(relativeUri)
	return jwksReq.DoRaw(ctx)
}

func requestAPIServer(ctx context.Context, caBundle []byte, apiserverURL, bearerToken string) (*metav1.Status, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiserverURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caBundle)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	status := &metav1.Status{}
	err = json.Unmarshal(body, status)
	if err != nil {
		return nil, err
	}

	return status, nil
}

type status struct {
	Code    int
	Message string
	Reason  string
	Status  string
}

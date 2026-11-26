// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"testing"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestManagedPrivateRegistryAccess(t *testing.T) {
	flavors := map[string]func(*clusterContext) ([]client.Object, error){
		"shoot": func(ctx *clusterContext) ([]client.Object, error) {
			return getShootRuntimeObjects(ctx, ptr.To[int32](1), "lakom", "access", "tls", true, false, false)
		},
		"seed": func(ctx *clusterContext) ([]client.Object, error) {
			return getSeedRuntimeObjects(ctx, ptr.To[int32](1), "tls", true, false, false)
		},
		"garden virtual": func(ctx *clusterContext) ([]client.Object, error) {
			return getGardenVirtualObjects(ctx, ptr.To[int32](1), "access", true, false, false)
		},
		"garden runtime": func(ctx *clusterContext) ([]client.Object, error) {
			return getGardenRuntimeObjects(ctx, ptr.To[int32](1), "tls", true, false, false)
		},
	}
	for flavor, render := range flavors {
		for _, enabled := range []bool{false, true} {
			t.Run(flavor+"/"+map[bool]string{false: "default", true: "opt-in"}[enabled], func(t *testing.T) {
				ctx := &clusterContext{
					namespace: "test", image: "example.org/lakom:test", kubernetesVersion: "1.35.0",
					lakomPublicKeysConfig: []byte("publicKeys: []"),
					generatedSecrets: map[string]*corev1.Secret{
						constants.GardenVirtualWebhookTLSSecretName: {ObjectMeta: metav1.ObjectMeta{Name: "tls"}},
					},
				}
				if enabled {
					ctx.allowedPrivateRegistryCIDRs = []string{"10.20.30.40/32", "fd12:3456::1/128"}
				}
				objects, err := render(ctx)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, object := range objects {
					deployment, ok := object.(*appsv1.Deployment)
					if !ok {
						continue
					}
					found = true
					labels := deployment.Spec.Template.Labels
					if (labels[v1beta1constants.LabelNetworkPolicyToPrivateNetworks] == v1beta1constants.LabelNetworkPolicyAllowed) != enabled {
						t.Fatalf("unexpected private network labels: %v", labels)
					}
					if _, present := labels[v1beta1constants.LabelNetworkPolicyToBlockedCIDRs]; present {
						t.Fatal("metadata access enabled despite image-pull-only configuration")
					}
					args := deployment.Spec.Template.Spec.Containers[0].Args
					for _, cidr := range ctx.allowedPrivateRegistryCIDRs {
						foundArg := false
						for _, arg := range args {
							if arg == "--allowed-private-registry-cidrs="+cidr {
								foundArg = true
							}
						}
						if !foundArg {
							t.Fatalf("missing CIDR %s in arguments", cidr)
						}
					}
				}
				if !found {
					t.Fatal("no deployment rendered")
				}
			})
		}
	}
}

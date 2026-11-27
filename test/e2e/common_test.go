// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"os"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var parentCtx context.Context

var _ = BeforeEach(func() {
	parentCtx = context.Background()
})

const projectNamespace = "garden-local"

func defaultShootCreationFramework() *framework.ShootCreationFramework {
	return newShootCreationFramework(true)
}

// defaultShootCreationFrameworkWithShootAccess returns a ShootCreationFramework configured to access the
// shoot cluster (SkipAccessingShoot: false).
func defaultShootCreationFrameworkWithShootAccess() *framework.ShootCreationFramework {
	return newShootCreationFramework(false)
}

func newShootCreationFramework(skipAccessingShoot bool) *framework.ShootCreationFramework {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	return framework.NewShootCreationFramework(&framework.ShootCreationConfig{
		GardenerConfig: &framework.GardenerConfig{
			ProjectNamespace:   projectNamespace,
			GardenerKubeconfig: kubeconfigPath,
			SkipAccessingShoot: skipAccessingShoot,
			CommonConfig:       &framework.CommonConfig{},
		},
	})
}

func ensureLakomServiceIsEnabled(shoot *gardencorev1beta1.Shoot) error {
	for i, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType {
			if e.Disabled != nil && *e.Disabled {
				shoot.Spec.Extensions[i].Disabled = new(false)
			}
			return nil
		}
	}

	shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
		Type:     constants.ExtensionType,
		Disabled: new(false),
	})
	return nil
}

func getLakomDeployment(ctx context.Context, c client.Client, namespace string) (*appsv1.Deployment, error) {
	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespace,
		},
	}

	err := c.Get(ctx, client.ObjectKeyFromObject(lakomDeployment), lakomDeployment)
	return lakomDeployment, err
}

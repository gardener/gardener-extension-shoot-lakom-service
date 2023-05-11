// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type kubeAPIServerMutator struct{}

func (m *kubeAPIServerMutator) Default(_ context.Context, obj runtime.Object) error {
	deployment, ok := obj.(*appsv1.Deployment)
	if !ok {
		return fmt.Errorf("expected *appsv1.Deployment but got %T", obj)
	}

	// TODO: This label approach is deprecated and no longer needed in the future. Remove it (and probably this entire webhook) as soon as gardener/gardener@v1.75 has been released.
	metav1.SetMetaDataLabel(&deployment.Spec.Template.ObjectMeta, gutil.NetworkPolicyLabel(constants.ExtensionServiceName, 10250), v1beta1constants.LabelNetworkPolicyAllowed)
	return nil
}

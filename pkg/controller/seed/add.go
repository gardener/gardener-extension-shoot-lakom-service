// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	controllerconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/config"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// Name is the name of the seed bootstrap controller.
	Name = "shoot_lakom_service_seed_bootstrap_controller"
)

// DefaultAddOptions contains configuration for the Lakom service.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the lakom service controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// ServiceConfig contains configuration for the shoot Lakom service.
	ServiceConfig controllerconfig.Config
}

// AddToManager adds a Lakom Service seed bootstrap controller to the given Controller Manager.
func AddToManager(_ context.Context, mgr manager.Manager) error {
	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("could not create Kubernetes clientset: %w", err)
	}

	k8sVersionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	k8sVersion, err := semver.NewVersion(k8sVersionInfo.GitVersion)
	if err != nil {
		return err
	}

	r := &kubeSystemReconciler{
		client:         mgr.GetClient(),
		seedK8sVersion: k8sVersion,
		serviceConfig:  DefaultAddOptions.ServiceConfig.Configuration,
	}

	DefaultAddOptions.ControllerOptions.Reconciler = r

	ctrl, err := controller.New(Name, mgr, DefaultAddOptions.ControllerOptions)
	if err != nil {
		return err
	}

	kubeSystemNamespacePredicate, err := predicate.LabelSelectorPredicate(
		metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{metav1.NamespaceSystem},
			}},
		},
	)
	if err != nil {
		return err
	}

	return ctrl.Watch(
		source.Kind(mgr.GetCache(), &corev1.Namespace{}),
		&handler.EnqueueRequestForObject{},
		kubeSystemNamespacePredicate,
	)
}

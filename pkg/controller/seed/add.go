// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	controllerconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/config"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
func AddToManager(mgr manager.Manager) error {
	r := &kubeSystemReconciler{
		client:        mgr.GetClient(),
		serviceConfig: DefaultAddOptions.ServiceConfig.Configuration,
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
		source.NewKindWithCache(&corev1.Namespace{}, mgr.GetCache()),
		&handler.EnqueueRequestForObject{},
		kubeSystemNamespacePredicate,
	)
}

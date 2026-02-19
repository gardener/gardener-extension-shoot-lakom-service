// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"

	"github.com/Masterminds/semver/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	ServiceConfig config.Configuration
	// SeedTopologyAwareRoutingEnabled determines whether the seed topology aware routing is enabled or not.
	SeedTopologyAwareRoutingEnabled bool
}

// AddToManager adds a Lakom Service seed bootstrap controller to the given Controller Manager.
func AddToManager(_ context.Context, mgr manager.Manager) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("could not create a discovery client: %w", err)
	}

	k8sVersionInfo, err := discoveryClient.ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to discover the Seed Kubernetes version: %w", err)
	}

	k8sVersion, err := semver.NewVersion(k8sVersionInfo.GitVersion)
	if err != nil {
		return fmt.Errorf("failed to parse the Seed Kubernetes version %q as semantic version: %w", k8sVersionInfo.GitVersion, err)
	}

	r := &kubeSystemReconciler{
		client:        mgr.GetClient(),
		serviceConfig: DefaultAddOptions.ServiceConfig,

		seedK8sVersion:                  k8sVersion,
		seedTopologyAwareRoutingEnabled: DefaultAddOptions.SeedTopologyAwareRoutingEnabled,
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

	return ctrl.Watch(source.Kind[client.Object](
		mgr.GetCache(),
		&corev1.Namespace{},
		&handler.EnqueueRequestForObject{},
		kubeSystemNamespacePredicate,
	))
}

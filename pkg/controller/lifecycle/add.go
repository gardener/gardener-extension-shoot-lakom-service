// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// Type is the type of Extension resource.
	Type = constants.ExtensionType
	// Name is the name of the lifecycle controller.
	Name = "shoot_lakom_service_lifecycle_controller"
	// FinalizerSuffix is the finalizer suffix for the Lakom Service controller.
	FinalizerSuffix = constants.ExtensionType
)

// DefaultAddOptions contains configuration for the Lakom service.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the lakom service controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// ServiceConfig contains configuration for the shoot Lakom service.
	ServiceConfig config.Configuration
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
	// ExtensionClasses contains the extension classes the controller should reconcile.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
}

// AddToManager adds a Lakom Service Lifecycle controller to the given Controller Manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return extension.Add(
		mgr,
		extension.AddArgs{
			Actuator:          NewActuator(mgr, DefaultAddOptions.ServiceConfig),
			ControllerOptions: DefaultAddOptions.ControllerOptions,
			ExtensionClasses:  DefaultAddOptions.ExtensionClasses,
			Name:              Name,
			FinalizerSuffix:   FinalizerSuffix,
			Resync:            60 * time.Minute,
			Predicates:        extension.DefaultPredicates(ctx, mgr, DefaultAddOptions.IgnoreOperationAnnotation),
			Type:              constants.ExtensionType,
		},
	)
}

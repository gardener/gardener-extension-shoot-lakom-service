// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	controllerconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/config"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"
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
	ServiceConfig controllerconfig.Config
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
}

// AddToManager adds a Lakom Service Lifecycle controller to the given Controller Manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return extension.Add(
		ctx,
		mgr,
		extension.AddArgs{
			Actuator:          NewActuator(mgr, DefaultAddOptions.ServiceConfig.Configuration),
			ControllerOptions: DefaultAddOptions.ControllerOptions,
			Name:              Name,
			FinalizerSuffix:   FinalizerSuffix,
			Resync:            60 * time.Minute,
			Predicates:        extension.DefaultPredicates(ctx, mgr, DefaultAddOptions.IgnoreOperationAnnotation),
			Type:              constants.ExtensionType,
		},
	)
}

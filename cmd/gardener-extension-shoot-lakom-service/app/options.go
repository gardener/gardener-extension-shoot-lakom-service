// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"

	lakomcmd "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/cmd"

	extensionscmdcontroller "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionsheartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
)

// ExtensionName is the name of the extension.
const ExtensionName = "shoot-lakom-service"

// Options holds configuration passed to the Lakom Service controller.
type Options struct {
	generalOptions       *extensionscmdcontroller.GeneralOptions
	lakomOptions         *lakomcmd.LakomServiceOptions
	restOptions          *extensionscmdcontroller.RESTOptions
	managerOptions       *extensionscmdcontroller.ManagerOptions
	lifecycleOptions     *extensionscmdcontroller.ControllerOptions
	seedBootstrapOptions *extensionscmdcontroller.ControllerOptions
	healthOptions        *extensionscmdcontroller.ControllerOptions
	heartbeatOptions     *extensionsheartbeatcmd.Options
	controllerSwitches   *extensionscmdcontroller.SwitchOptions
	reconcileOptions     *extensionscmdcontroller.ReconcilerOptions
	optionAggregator     extensionscmdcontroller.OptionAggregator
}

// NewOptions creates a new Options instance.
func NewOptions() *Options {

	options := &Options{
		generalOptions: &extensionscmdcontroller.GeneralOptions{},
		lakomOptions:   &lakomcmd.LakomServiceOptions{},
		restOptions:    &extensionscmdcontroller.RESTOptions{},
		managerOptions: &extensionscmdcontroller.ManagerOptions{
			// These are default values.
			LeaderElection:          true,
			LeaderElectionID:        extensionscmdcontroller.LeaderElectionNameID(ExtensionName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		lifecycleOptions: &extensionscmdcontroller.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		seedBootstrapOptions: &extensionscmdcontroller.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 1,
		},
		healthOptions: &extensionscmdcontroller.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		heartbeatOptions: &extensionsheartbeatcmd.Options{
			// This is a default value.
			ExtensionName:        ExtensionName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		reconcileOptions:   &extensionscmdcontroller.ReconcilerOptions{},
		controllerSwitches: lakomcmd.ControllerSwitches(),
	}

	options.optionAggregator = extensionscmdcontroller.NewOptionAggregator(
		options.generalOptions,
		options.lakomOptions,
		options.restOptions,
		options.managerOptions,
		extensionscmdcontroller.PrefixOption("lifecycle-", options.lifecycleOptions),
		extensionscmdcontroller.PrefixOption("seed-bootstrap-", options.seedBootstrapOptions),
		extensionscmdcontroller.PrefixOption("healthcheck-", options.healthOptions),
		extensionscmdcontroller.PrefixOption("heartbeat-", options.heartbeatOptions),
		options.controllerSwitches,
		options.reconcileOptions,
	)

	return options
}

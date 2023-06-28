// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"

	lakomcmd "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/cmd"

	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	heartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
)

// ExtensionName is the name of the extension.
const ExtensionName = "shoot-lakom-service"

// Options holds configuration passed to the Lakom Service controller.
type Options struct {
	generalOptions       *controllercmd.GeneralOptions
	lakomOptions         *lakomcmd.LakomServiceOptions
	restOptions          *controllercmd.RESTOptions
	managerOptions       *controllercmd.ManagerOptions
	lifecycleOptions     *controllercmd.ControllerOptions
	seedBootstrapOptions *controllercmd.ControllerOptions
	healthOptions        *controllercmd.ControllerOptions
	heartbeatOptions     *heartbeatcmd.Options
	controllerSwitches   *controllercmd.SwitchOptions
	reconcileOptions     *controllercmd.ReconcilerOptions
	optionAggregator     controllercmd.OptionAggregator
}

// NewOptions creates a new Options instance.
func NewOptions() *Options {

	options := &Options{
		generalOptions: &controllercmd.GeneralOptions{},
		lakomOptions:   &lakomcmd.LakomServiceOptions{},
		restOptions:    &controllercmd.RESTOptions{},
		managerOptions: &controllercmd.ManagerOptions{
			// These are default values.
			LeaderElection:          true,
			LeaderElectionID:        controllercmd.LeaderElectionNameID(ExtensionName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		lifecycleOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		seedBootstrapOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 1,
		},
		healthOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		heartbeatOptions: &heartbeatcmd.Options{
			// This is a default value.
			ExtensionName:        ExtensionName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		reconcileOptions:   &controllercmd.ReconcilerOptions{},
		controllerSwitches: lakomcmd.ControllerSwitches(),
	}

	options.optionAggregator = controllercmd.NewOptionAggregator(
		options.generalOptions,
		options.lakomOptions,
		options.restOptions,
		options.managerOptions,
		controllercmd.PrefixOption("lifecycle-", options.lifecycleOptions),
		controllercmd.PrefixOption("seed-bootstrap-", options.seedBootstrapOptions),
		controllercmd.PrefixOption("healthcheck-", options.healthOptions),
		controllercmd.PrefixOption("heartbeat-", options.heartbeatOptions),
		options.controllerSwitches,
		options.reconcileOptions,
	)

	return options
}

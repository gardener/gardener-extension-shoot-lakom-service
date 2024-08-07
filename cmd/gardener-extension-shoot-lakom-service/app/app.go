// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"net/http"
	"runtime"

	apilakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	v1alpha1apilakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/healthcheck"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/lifecycle"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/seed"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/controllerutils/routes"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	log = logf.Log
)

// NewServiceControllerCommand creates a new command that is used to start the Lakom Service controller.
func NewServiceControllerCommand() *cobra.Command {
	options := NewOptions()

	cmd := &cobra.Command{
		Use:           constants.GardenerExtensionName,
		Short:         "Lakom Service Controller manages components which provide lakom admission controller.",
		SilenceErrors: true,

		RunE: func(cmd *cobra.Command, _ []string) error {
			verflag.PrintAndExitIfRequested()

			if err := options.optionAggregator.Complete(); err != nil {
				return fmt.Errorf("error completing options: %s", err)
			}
			log.Info("Starting "+constants.GardenerExtensionName, "version", version.Get())
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Info(fmt.Sprintf("FLAG: --%s=%s", flag.Name, flag.Value))
			})

			if err := options.heartbeatOptions.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return options.run(cmd.Context())
		},
	}

	verflag.AddFlags(cmd.Flags())
	options.optionAggregator.AddFlags(cmd.Flags())

	return cmd
}

func (o *Options) run(ctx context.Context) error {
	// TODO: Make these flags configurable via command line parameters or component config file.
	util.ApplyClientConnectionConfigurationToRESTConfig(&componentbaseconfig.ClientConnectionConfiguration{
		QPS:   100.0,
		Burst: 130,
	}, o.restOptions.Completed().Config)

	var (
		extraHandlers map[string]http.Handler
		ctrlConfig    = o.lakomOptions.Completed()
		debugConfig   = &config.Config{}
		mgrOpts       = o.managerOptions.Completed().Options()
	)

	ctrlConfig.Apply(debugConfig)
	if debugConfig.DebugConfig.EnableProfiling {
		extraHandlers = routes.ProfilingHandlers

		if debugConfig.DebugConfig.EnableContentionProfiling {
			runtime.SetBlockProfileRate(1)
		}
	}
	mgrOpts.Metrics.ExtraHandlers = extraHandlers

	mgrOpts.Client = client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{
				&corev1.Secret{},    // applied for ManagedResources
				&corev1.ConfigMap{}, // applied for monitoring config
			},
		},
	}

	mgr, err := manager.New(o.restOptions.Completed().Config, mgrOpts)
	if err != nil {
		return fmt.Errorf("could not instantiate controller-manager: %s", err)
	}

	if err := extensionscontroller.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %s", err)
	}
	if err := monitoringv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}
	if err := v1alpha1apilakom.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}
	if err := apilakom.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	ctrlConfig.ApplyHealthCheckConfig(&healthcheck.DefaultAddOptions.HealthCheckConfig)
	ctrlConfig.Apply(&lifecycle.DefaultAddOptions.ServiceConfig)
	ctrlConfig.Apply(&seed.DefaultAddOptions.ServiceConfig)
	o.lifecycleOptions.Completed().Apply(&lifecycle.DefaultAddOptions.ControllerOptions)
	o.seedBootstrapOptions.Completed().Apply(&seed.DefaultAddOptions.ControllerOptions)
	o.healthOptions.Completed().Apply(&healthcheck.DefaultAddOptions.Controller)
	o.heartbeatOptions.Completed().Apply(&heartbeat.DefaultAddOptions)

	if err := o.controllerSwitches.Completed().AddToManager(ctx, mgr); err != nil {
		return fmt.Errorf("could not add controllers to manager: %s", err)
	}

	if err := configureHealthCheck(mgr); err != nil {
		return fmt.Errorf("failed to setup webhook server")
	}

	return mgr.Start(ctx)
}

// configureHealthCheck configures the healthiness and readiness checkers.
// Also, if enabled, sets the profiling endpoints.
func configureHealthCheck(mgr manager.Manager) error {
	log.Info("Setting up health check endpoints")
	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return err
	}

	return mgr.AddHealthzCheck("ping", healthz.Ping)
}

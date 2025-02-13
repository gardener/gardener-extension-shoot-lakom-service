// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"os"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	apisconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	v1alpha1apisconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config/v1alpha1"
	healthcheckcontroller "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/healthcheck"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/lifecycle"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/seed"

	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
	"github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionshealthcheckcontroller "github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	extensionsheartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	scheme  *runtime.Scheme
	decoder runtime.Decoder
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(apisconfig.AddToScheme(scheme))
	utilruntime.Must(v1alpha1apisconfig.AddToScheme(scheme))

	decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
}

// LakomServiceOptions holds options related to the Lakom service.
type LakomServiceOptions struct {
	ConfigLocation string
	config         *LakomServiceConfig
}

// AddFlags implements Flagger.AddFlags.
func (o *LakomServiceOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigLocation, "config", "", "Path to lakom service configuration")
}

// Complete implements Completer.Complete.
func (o *LakomServiceOptions) Complete() error {
	if o.ConfigLocation == "" {
		return errors.New("config location is not set")
	}
	data, err := os.ReadFile(o.ConfigLocation)
	if err != nil {
		return err
	}

	config := apisconfig.Configuration{}
	_, _, err = decoder.Decode(data, nil, &config)
	if err != nil {
		return err
	}

	o.config = &LakomServiceConfig{
		config: config,
	}

	return nil
}

// Completed returns the decoded LakomServiceConfig instance. Only call this if `Complete` was successful.
func (o *LakomServiceOptions) Completed() *LakomServiceConfig {
	return o.config
}

// LakomServiceConfig contains configuration information about the Lakom service.
type LakomServiceConfig struct {
	config apisconfig.Configuration
}

// Apply applies the LakomServiceOptions to the passed ControllerOptions instance.
func (c *LakomServiceConfig) Apply(config *config.Configuration) {
	*config = c.config
}

// ApplyHealthCheckConfig applies the HealthCheckConfig to the config.
func (c *LakomServiceConfig) ApplyHealthCheckConfig(config *healthcheckconfig.HealthCheckConfig) {
	if c.config.HealthCheckConfig != nil {
		*config = *c.config.HealthCheckConfig
	}
}

// ControllerSwitches are the cmd.ControllerSwitches for the extension controllers.
func ControllerSwitches() *cmd.SwitchOptions {
	return cmd.NewSwitchOptions(
		cmd.Switch(lifecycle.Name, lifecycle.AddToManager),
		cmd.Switch(seed.Name, seed.AddToManager),
		cmd.Switch(extensionshealthcheckcontroller.ControllerName, healthcheckcontroller.AddToManager),
		cmd.Switch(extensionsheartbeatcontroller.ControllerName, extensionsheartbeatcontroller.AddToManager),
	)
}

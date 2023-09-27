// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	goruntime "runtime"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/admission"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/resolvetag"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	"github.com/gardener/gardener/pkg/controllerutils/routes"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	gracefulShutdownTimeout = 5 * time.Second
	log                     = logf.Log
)

// NewAdmissionCommand creates a new *cobra.Command able to run lakom admission controller.
func NewAdmissionCommand() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   constants.ApplicationName,
		Short: "Launch the " + constants.ApplicationName,
		Long:  constants.ApplicationName + " serves validating and mutating webhook endpoints for cosign image signature validation.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			if err := opts.validate(); err != nil {
				return err
			}

			log.Info("Starting "+constants.ApplicationName, "version", version.Get())
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Info(fmt.Sprintf("FLAG: --%s=%s", flag.Name, flag.Value))
			})

			return opts.Run(cmd.Context())
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	flags.AddGoFlagSet(flag.CommandLine)
	verflag.AddFlags(flags)
	opts.AddFlags(flags)
	return cmd
}

// Options has all the context and parameters needed to run lakom admission controller.
type Options struct {
	// BindAddress is the address the HTTP server should bind to.
	BindAddress string
	// Port is the port that should be opened by the HTTP server.
	Port int
	// ServerCertDir is the path to server TLS cert and key.
	ServerCertDir string
	// MetricsBindAddress is the TCP address that the controller should bind to
	// for serving prometheus metrics.
	// It can be set to "0" to disable the metrics serving.
	MetricsBindAddress string
	// HealthBindAddress is the TCP address that the controller should bind to for serving health probes.
	HealthBindAddress string
	// EnableProfiling enables profiling via web interface host:port/debug/pprof/.
	EnableProfiling bool
	// EnableContentionProfiling enables lock contention profiling, if
	// enableProfiling is true.
	EnableContentionProfiling bool
	// CosignPublicKeyPath is path to file with cosign public key used to verify the image signatures.
	CosignPublicKeyPath string
	// CacheTTL is the duration the objects are kept in the cache.
	CacheTTL time.Duration
	// CacheRefreshInterval is the duration between cache evaluations if a given object needs to dropped from the cache or not.
	CacheRefreshInterval time.Duration
}

// AddFlags adds lakom admission controller's flags to the specified FlagSet.
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.BindAddress, "bind-address", "0.0.0.0", "Address to bind to")
	fs.IntVar(&o.Port, "port", 9443, "Webhook server port")
	fs.StringVar(&o.ServerCertDir, "tls-cert-dir", "", "Directory with server TLS certificate and key (must contain a tls.crt and tls.key file)")
	fs.StringVar(&o.MetricsBindAddress, "metrics-bind-address", ":8080", "Bind address for the metrics server")
	fs.StringVar(&o.HealthBindAddress, "health-bind-address", ":8081", "Bind address for the health server")
	fs.BoolVar(&o.EnableProfiling, "profiling", false, "Enable profiling via web interface host:port/debug/pprof/")
	fs.BoolVar(&o.EnableContentionProfiling, "contention-profiling", false, "Enable lock contention profiling, if profiling is enabled")
	fs.StringVar(&o.CosignPublicKeyPath, "cosign-public-key-path", "", "Path to file with cosign public key used to verify the image signatures")
	fs.DurationVar(&o.CacheTTL, "cache-ttl", time.Minute*10, "TTL for the cached objects. Set to 0, if cache has to be disabled")
	fs.DurationVar(&o.CacheRefreshInterval, "cache-refresh-interval", time.Second*30, "Refresh interval for the cached objects")
}

// validate validates all the required options.
func (o *Options) validate() error {
	if len(o.BindAddress) == 0 {
		return fmt.Errorf("missing bind address")
	}

	if o.Port == 0 {
		return fmt.Errorf("missing port")
	}

	if len(o.ServerCertDir) == 0 {
		return fmt.Errorf("missing server tls cert path")
	}

	if len(o.CosignPublicKeyPath) == 0 {
		return fmt.Errorf("missing cosign public key path")
	}

	if o.CacheTTL != 0 {
		if o.CacheRefreshInterval == 0 {
			return fmt.Errorf("cache refresh interval cannot be zero")
		}

		if o.CacheTTL < o.CacheRefreshInterval {
			return fmt.Errorf("cache refresh interval cannot be greater than cache TTL")
		}
	}

	return nil
}

// Run runs lakom admission controller using the specified options.
func (o *Options) Run(ctx context.Context) error {
	log.Info("Getting rest config")
	restConfig, err := config.GetConfig()
	if err != nil {
		return err
	}

	log.Info("Building scheme")
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}

	var extraHandlers map[string]http.Handler
	if o.EnableProfiling {
		extraHandlers = routes.ProfilingHandlers
		if o.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}

	log.Info("Setting up manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Scheme:         scheme,
		LeaderElection: false,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    o.Port,
			Host:    o.BindAddress,
			CertDir: o.ServerCertDir,
		}),
		Metrics: metricsserver.Options{
			BindAddress:   o.MetricsBindAddress,
			ExtraHandlers: extraHandlers,
		},
		HealthProbeBindAddress:  o.HealthBindAddress,
		GracefulShutdownTimeout: &gracefulShutdownTimeout,
	})
	if err != nil {
		return err
	}

	log.Info("Setting up healthiness check endpoints")
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}

	log.Info("Setting up webhook server")
	server := mgr.GetWebhookServer()

	log.Info("Setting up readiness check for webhook server")
	if err := mgr.AddReadyzCheck("webhook-server", server.StartedChecker()); err != nil {
		return err
	}

	imageTagResolverHandler, err := resolvetag.NewHandleBuilder().
		WithManager(mgr).
		WithLogger(log.WithName("image-tag-resolver")).
		WithCacheTTL(o.CacheTTL).
		WithCacheRefreshInterval(o.CacheRefreshInterval).
		Build()
	if err != nil {
		return err
	}

	reader, err := os.Open(o.CosignPublicKeyPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Error(err, "failed to close file", "filePath", o.CosignPublicKeyPath)
		}
	}()

	cosignSignatureVerifyHandler, err := verifysignature.NewHandleBuilder().
		WithManager(mgr).
		WithLogger(log.WithName("cosign-signature-verifier")).
		WithCosignPublicKeysReader(reader).
		WithCacheTTL(o.CacheTTL).
		WithCacheRefreshInterval(o.CacheRefreshInterval).
		Build()
	if err != nil {
		return err
	}

	server.Register(
		constants.LakomResolveTagPath,
		&admission.Server{
			Webhook: webhook.Admission{Handler: imageTagResolverHandler},
			Log:     imageTagResolverHandler.GetLogger(),
		},
	)
	server.Register(
		constants.LakomVerifyCosignSignaturePath,
		&admission.Server{
			Webhook: webhook.Admission{Handler: cosignSignatureVerifyHandler},
			Log:     cosignSignatureVerifyHandler.GetLogger(),
		},
	)

	log.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Error(err, "Error running manager")
		return err
	}

	return nil
}

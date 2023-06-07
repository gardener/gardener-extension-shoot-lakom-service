// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/admission"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/resolvetag"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	"github.com/gardener/gardener/pkg/controllerutils/routes"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	crwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
)

const (
	// Name is the name of lakom seed admission controller.
	Name = constants.GardenerExtensionName + "-seed"
)

// DefaultConfig is the config with the default values.
var DefaultConfig = Config{}

// Config controls the behavior of the lakom seed admission controller.
type Config struct {
	// CosignPublicKeys is list of cosign public keys used to verify the OCI image signatures.
	CosignPublicKeys []string
	// FailurePolicy is the failure policy of the admission configuration.
	FailurePolicy string
	// EnableProfiling enables profiling via web interface host:port/debug/pprof/.
	EnableProfiling bool
	// EnableContentionProfiling enables lock contention profiling, if
	// enableProfiling is true.
	EnableContentionProfiling bool
}

// AddToManagerWithDefaultConfig adds the lakom seed admission controller to the Manager with the default configuration.
func AddToManagerWithDefaultConfig(ctx context.Context, mgr manager.Manager, config Config) error {

	log := log.Log.WithName(Name)

	log.Info("Setting up webhook server")
	server := mgr.GetWebhookServer()

	if err := mgr.AddReadyzCheck("webhook-server", server.StartedChecker()); err != nil {
		return err
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}

	if config.EnableProfiling {
		if err := (routes.Profiling{}).AddToManager(mgr); err != nil {
			return err
		}

		if config.EnableContentionProfiling {
			runtime.SetBlockProfileRate(1)
		}
	}

	imageTagResolverHandler, err := resolvetag.NewHandleBuilder().
		WithLogger(log.WithName("image-tag-resolver")).
		WithCacheTTL(time.Minute * 10).
		WithCacheRefreshInterval(time.Second * 30).
		Build(ctx)
	if err != nil {
		return err
	}

	reader := strings.NewReader(strings.Join(config.CosignPublicKeys, "\n"))
	cosignSignatureVerifyHandler, err := verifysignature.NewHandleBuilder().
		WithLogger(log.WithName("cosign-signature-verifier")).
		WithCosignPublicKeysReader(reader).
		WithCacheTTL(time.Minute * 10).
		WithCacheRefreshInterval(time.Second * 30).
		Build(ctx)
	if err != nil {
		return err
	}

	server.Register(
		constants.LakomResolveTagPath,
		&admission.Server{Webhook: crwebhook.Admission{Handler: imageTagResolverHandler}},
	)
	server.Register(
		constants.LakomVerifyCosignSignaturePath,
		&admission.Server{Webhook: crwebhook.Admission{Handler: cosignSignatureVerifyHandler}},
	)

	return nil
}

// AddToManager adds all webhook handlers to the given manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return AddToManagerWithDefaultConfig(ctx, mgr, DefaultConfig)
}

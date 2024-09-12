// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/gardener/gardener-extension-shoot-lakom-service/cmd/gardener-extension-shoot-lakom-admission/app"

	"github.com/gardener/gardener/pkg/logger"
	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

func main() {
	runtimelog.SetLogger(logger.MustNewZapLogger(logger.InfoLevel, logger.FormatJSON))
	cmd := app.NewAdmissionCommand(signals.SetupSignalHandler())

	if err := cmd.Execute(); err != nil {
		runtimelog.Log.Error(err, "error executing the main controller command")
		os.Exit(1)
	}
}

// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/gardener/gardener-extension-shoot-lakom-service/cmd/gardener-extension-shoot-lakom-service/app"

	"github.com/gardener/gardener/pkg/logger"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

func main() {
	logf.SetLogger(logger.MustNewZapLogger(logger.InfoLevel, logger.FormatJSON))

	ctx := signals.SetupSignalHandler()
	if err := app.NewServiceControllerCommand().ExecuteContext(ctx); err != nil {
		logf.Log.Error(err, "error executing the main controller command")
		os.Exit(1)
	}
}

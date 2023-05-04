// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/healthcheck"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/lifecycle"
	lakomwebhook "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/controller/webhook"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/certificates"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			if err := options.optionAggregator.Complete(); err != nil {
				return fmt.Errorf("error completing options: %s", err)
			}
			log.Info("Starting "+constants.GardenerExtensionName, "version", version.Get())
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Info(fmt.Sprintf("FLAG: --%s=%s", flag.Name, flag.Value)) //nolint:logcheck
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

	mgrOpts := o.managerOptions.Completed().Options()

	mgrOpts.ClientDisableCacheFor = []client.Object{
		&corev1.Secret{},    // applied for ManagedResources
		&corev1.ConfigMap{}, // applied for monitoring config
	}

	mgr, err := manager.New(o.restOptions.Completed().Config, mgrOpts)
	if err != nil {
		return fmt.Errorf("could not instantiate controller-manager: %s", err)
	}

	if err := extensionscontroller.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %s", err)
	}

	ctrlConfig := o.lakomOptions.Completed()
	ctrlConfig.ApplyHealthCheckConfig(&healthcheck.DefaultAddOptions.HealthCheckConfig)
	ctrlConfig.Apply(&lifecycle.DefaultAddOptions.ServiceConfig)
	ctrlConfig.ApplyWebhookConfig(&lakomwebhook.DefaultConfig)
	o.lifecycleOptions.Completed().Apply(&lifecycle.DefaultAddOptions.ControllerOptions)
	o.healthOptions.Completed().Apply(&healthcheck.DefaultAddOptions.Controller)
	o.heartbeatOptions.Completed().Apply(&heartbeat.DefaultAddOptions)

	var (
		mode          = webhook.ModeService
		name          = lakomwebhook.Name
		url           = name
		namespaceName = mgrOpts.LeaderElectionNamespace
	)

	validatingWebhookConfig, mutatingWebhookConfig := lakomwebhook.GetWebhookConfigurations(mode, url, namespaceName, *lifecycle.DefaultAddOptions.ServiceConfig.FailurePolicy)

	if err := certificates.AddCertificateManagementToManager(
		ctx,
		mgr,
		clock.RealClock{},
		validatingWebhookConfig,
		nil,
		nil,
		nil,
		"",
		name,
		namespaceName,
		mode,
		url,
	); err != nil {
		return fmt.Errorf("failed adding validating webhook certificate management to manager: %w", err)
	}

	if err := o.controllerSwitches.Completed().AddToManager(mgr); err != nil {
		return fmt.Errorf("could not add controllers to manager: %s", err)
	}

	log.Info("Adding runnables to manager")
	if err := mgr.Add(&controllerutils.ControlledRunner{
		Manager: mgr,
		BootstrapRunnables: []manager.Runnable{
			reconcileValidatingWebhookConfiguration(ctx, mgr, namespaceName, validatingWebhookConfig),
			reconcileMutatingWebhookConfiguration(ctx, mgr, namespaceName, mutatingWebhookConfig),
		},
		ActualRunnables: []manager.Runnable{
			manager.RunnableFunc(func(context.Context) error {
				return lakomwebhook.AddWebhookCABundleReconcilerToManager(ctx, mgr, validatingWebhookConfig.GetName(), mutatingWebhookConfig.GetName())
			}),
		},
	}); err != nil {
		return err
	}

	if err := lakomwebhook.AddToManager(ctx, mgr); err != nil {
		return err
	}

	return mgr.Start(ctx)
}

func reconcileValidatingWebhookConfiguration(ctx context.Context, mgr manager.Manager, namespaceName string, validatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration) manager.RunnableFunc {
	return func(context.Context) error {
		mgr.GetLogger().Info("Reconciling webhook configuration", "validatingWebhookConfiguration", client.ObjectKeyFromObject(validatingWebhookConfiguration))

		mgrClient := mgr.GetClient()
		namespace, err := getNamespace(ctx, mgrClient, namespaceName)
		if err != nil {
			return fmt.Errorf("could not get namespace %s: %s", namespaceName, err)
		}

		ownerRef := metav1.NewControllerRef(namespace, corev1.SchemeGroupVersion.WithKind("Namespace"))
		ownerRef.BlockOwnerDeletion = pointer.Bool(false)

		obj := &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: validatingWebhookConfiguration.Name}}
		_, err = controllerutils.CreateOrGetAndStrategicMergePatch(ctx, mgrClient, obj, func() error {
			obj.Webhooks = validatingWebhookConfiguration.Webhooks
			obj.SetOwnerReferences(kubernetes.MergeOwnerReferences(obj.GetOwnerReferences(), *ownerRef))
			if obj.Labels == nil {
				obj.Labels = map[string]string{}
			}
			obj.Labels[v1beta1constants.LabelExcludeWebhookFromRemediation] = "true"
			return nil
		})
		validatingWebhookConfiguration = obj
		return err
	}
}

func reconcileMutatingWebhookConfiguration(ctx context.Context, mgr manager.Manager, namespaceName string, mutatingWebhookConfiguration *admissionregistrationv1.MutatingWebhookConfiguration) manager.RunnableFunc {
	return func(context.Context) error {
		mgr.GetLogger().Info("Reconciling webhook configuration", "mutatingWebhookConfiguration", client.ObjectKeyFromObject(mutatingWebhookConfiguration))

		mgrClient := mgr.GetClient()
		namespace, err := getNamespace(ctx, mgrClient, namespaceName)
		if err != nil {
			return fmt.Errorf("could not get namespace %s: %s", namespaceName, err)
		}

		ownerRef := metav1.NewControllerRef(namespace, corev1.SchemeGroupVersion.WithKind("Namespace"))
		ownerRef.BlockOwnerDeletion = pointer.Bool(false)

		obj := &admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: mutatingWebhookConfiguration.Name}}
		_, err = controllerutils.CreateOrGetAndStrategicMergePatch(ctx, mgrClient, obj, func() error {
			obj.Webhooks = mutatingWebhookConfiguration.Webhooks
			obj.SetOwnerReferences(kubernetes.MergeOwnerReferences(obj.GetOwnerReferences(), *ownerRef))
			if obj.Labels == nil {
				obj.Labels = map[string]string{}
			}
			obj.Labels[v1beta1constants.LabelExcludeWebhookFromRemediation] = "true"
			return nil
		})
		mutatingWebhookConfiguration = obj
		return err
	}
}

func getNamespace(ctx context.Context, c client.Client, namespaceName string) (*corev1.Namespace, error) {
	namespace := corev1.Namespace{}

	if err := c.Get(ctx, client.ObjectKey{Name: namespaceName}, &namespace); err != nil {
		return nil, err
	}
	return &namespace, nil
}

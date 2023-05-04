// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	"github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var (
	// DefaultSyncPeriod is the default sync period of the controller.
	DefaultSyncPeriod = time.Minute * 5
)

// GetWebhookConfigurations returns the webhook configuration for the given mode and URL.
func GetWebhookConfigurations(mode, url, namespaceName, failurePolicyConfig string) (*admissionregistrationv1.ValidatingWebhookConfiguration, *admissionregistrationv1.MutatingWebhookConfiguration) {
	var (
		objectMeta = metav1.ObjectMeta{
			Name: Name,
			Labels: map[string]string{
				v1beta1constants.LabelExcludeWebhookFromRemediation: "true",
			},
		}
		sideEffects       = admissionregistrationv1.SideEffectClassNone
		matchPolicy       = admissionregistrationv1.Exact
		failurePolicy     = admissionregistrationv1.FailurePolicyType(failurePolicyConfig)
		failurePolicyFail = admissionregistrationv1.Fail
		namespaceSelector = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      corev1.LabelMetadataName,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{metav1.NamespaceSystem, namespaceName},
				},
			},
		}
		rules = []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.SchemeGroupVersion.Group},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods", "pods/ephemeralcontainers"},
			},
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
		}}
		validatingClientConfig = webhook.BuildClientConfigFor(
			constants.LakomVerifyCosignSignaturePath,
			namespaceName,
			Name,
			443,
			mode,
			url,
			nil,
		)
		mutatingClientConfig = webhook.BuildClientConfigFor(
			constants.LakomResolveTagPath,
			namespaceName,
			Name,
			443,
			mode,
			url,
			nil,
		)
	)

	validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: objectMeta,
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:                    "verify-signature.lakom.seed.service.extensions.gardener.cloud",
				ClientConfig:            validatingClientConfig,
				AdmissionReviewVersions: []string{"v1", "v1beta1"},
				Rules:                   rules,
				NamespaceSelector:       &namespaceSelector,
				SideEffects:             &sideEffects,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          pointer.Int32(25),
			},
		},
	}

	mutatingWebhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: objectMeta,
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:                    "resolve-tag.lakom.seed.service.extensions.gardener.cloud",
				ClientConfig:            mutatingClientConfig,
				AdmissionReviewVersions: []string{"v1", "v1beta1"},
				Rules:                   rules,
				NamespaceSelector:       &namespaceSelector,
				SideEffects:             &sideEffects,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          pointer.Int32(25),
			},
			{
				Name: "mutate-kube-apiserver.lakom.seed.service.extensions.gardener.cloud",
				ClientConfig: webhook.BuildClientConfigFor(
					constants.LakomMutateKubeAPIServer,
					namespaceName,
					Name,
					443,
					mode,
					url,
					nil,
				),
				AdmissionReviewVersions: []string{"v1", "v1beta1"},
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{appsv1.SchemeGroupVersion.Group},
						APIVersions: []string{appsv1.SchemeGroupVersion.Version},
						Resources:   []string{"deployments"},
					},
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
				}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					v1beta1constants.GardenRole:                            v1beta1constants.GardenRoleShoot,
					"extensions.gardener.cloud/" + constants.ExtensionType: "true",
				}},
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					v1beta1constants.LabelApp:  v1beta1constants.LabelKubernetes,
					v1beta1constants.LabelRole: v1beta1constants.LabelAPIServer,
				}},
				SideEffects:    &sideEffects,
				FailurePolicy:  &failurePolicyFail,
				MatchPolicy:    &matchPolicy,
				TimeoutSeconds: pointer.Int32(10),
			},
		},
	}

	return validatingWebhookConfiguration, mutatingWebhookConfiguration
}

// webhookCABundleReconciler is controller that replicates the CA bundle of given ValidatingWebhookConfiguration to MutatingWebhookConfiguration.
type webhookCABundleReconciler struct {
	// sourceName is the name of watched validating webhook config
	sourceName string

	// targetName is the name of the target mutating webhook config
	targetName string

	client client.Client

	syncPeriod time.Duration
}

// AddWebhookCABundleReconcilerToManager adds the webhookCABundleReconciler to the manager.
func AddWebhookCABundleReconcilerToManager(ctx context.Context, mgr manager.Manager, sourceName, targetName string) error {
	r := &webhookCABundleReconciler{
		client:     mgr.GetClient(),
		sourceName: sourceName,
		targetName: targetName,
		syncPeriod: DefaultSyncPeriod,
	}

	name := "webhook-ca-bundle-reconciler-" + sourceName
	ctrl, err := controller.New(name, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	return ctrl.Watch(
		source.NewKindWithCache(&admissionregistrationv1.ValidatingWebhookConfiguration{}, mgr.GetCache()),
		&handler.EnqueueRequestForObject{},
	)
}

// Reconcile replicates the CA bundle from the source to the target webhook config.
func (r *webhookCABundleReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req.Name != r.sourceName {
		return reconcile.Result{}, nil
	}

	source := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.sourceName,
		},
	}

	if err := r.client.Get(ctx, client.ObjectKeyFromObject(source), source); err != nil {
		return reconcile.Result{}, err
	}

	var caBundle []byte

	for _, webhook := range source.Webhooks {
		if len(webhook.ClientConfig.CABundle) == 0 {
			continue
		}
		caBundle = webhook.ClientConfig.CABundle
		break
	}

	if len(caBundle) == 0 {
		return reconcile.Result{}, fmt.Errorf("no CA bundle available in the source validating webhook config %v", source.GetName())
	}

	target := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.targetName,
		},
	}

	if err := r.client.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
		return reconcile.Result{}, err
	}

	injected := target.DeepCopy()
	if err := webhook.InjectCABundleIntoWebhookConfig(injected, caBundle); err != nil {
		return reconcile.Result{}, err
	}

	patch := client.MergeFromWithOptions(target, client.MergeFromWithOptimisticLock{})
	err := r.client.Patch(ctx, injected, patch)

	return reconcile.Result{RequeueAfter: r.syncPeriod}, err
}

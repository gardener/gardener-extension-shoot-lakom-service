# Introduction

This extension implements [cosign](https://github.com/sigstore/cosign) image verification. It is strictly limited only to the kubernetes system components deployed by Gardener and other Gardener Extensions in the `kube-system` namespace of a shoot cluster.

## Shoot Feature Gate

In most of the Gardener setups the `shoot-lakom-service` extension is enabled globally and thus can be configured per shoot cluster. Please adapt the shoot specification by the configuration shown below to disable the extension individually.

```yaml
kind: Shoot
...
spec:
  resources:
  - name: lakom-ref
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: lakom-secret
  extensions:
  - type: shoot-lakom-service
    disabled: true
    providerConfig:
      apiVersion: lakom.extensions.gardener.cloud/v1alpha1
      kind: LakomConfig
      scope: KubeSystem
      publicKeysSecretReference: lakom-ref
...
```

The `scope` field instruct lakom which pods to validate. The possible values are:

- `KubeSystem`
Lakom will validate all pods in the `kube-system` namespace.
- `KubeSystemManagedByGardener`
Lakom will validate all pods in the `kube-system` namespace that are annotated with "managed-by/gardener"
- `Cluster`
Lakom will validate all pods in all namespaces.


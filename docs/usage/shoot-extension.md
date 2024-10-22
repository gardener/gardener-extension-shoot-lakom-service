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

### Scope

The `scope` field instruct lakom which pods to validate. The possible values are:

- `KubeSystem`
Lakom will validate all pods in the `kube-system` namespace.
- `KubeSystemManagedByGardener`
Lakom will validate all pods in the `kube-system` namespace that are annotated with "managed-by/gardener". This is the default value.
- `Cluster`
Lakom will validate all pods in all namespaces.

### TrustedKeysResourceName

Lakom, by default, tries to verify only workloads that belong to Gardener. Because of this, the only public keys that it uses to do its job are the ones for the Gardener workload.

If you'd like to use Lakom as a tool for verifying your own workload, you'll need to add your own public keys to the ones that Lakom is already using. This can be achieved using Gardener [referenced resources](https://github.com/gardener/gardener/blob/master/docs/extensions/referenced-resources.md). More information about the keys and their format can be found [here](https://github.com/gardener/gardener-extension-shoot-lakom-service/blob/main/docs/usage/lakom.md#lakom-cosign-public-keys-configuration-file).

Simply:
1. Create a secret in your project namespace that contains a field `keys` with your keys as a value. Example keys:
```
- name: example-client-key1
  algorithm: RSASSA-PSS-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPeQXbIWMMXYV+9+j9b4jXTflnpfwn4E
    GMrmqYVhm0sclXb2FPP5aV/NFH6SZdHDZcT8LCNsNgxzxV4N+UE/JIsCAwEAAQ==
    -----END PUBLIC KEY-----
- name: example-client-key2
  algorithm: RSASSA-PSS-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPeQXbIWMMXYV+9+j9b4jXTflnpfwn4E
    GMrmqYVhm0sclXb2FPP5aV/NFH6SZdHDZcT8LCNsNgxzxV4N+UE/JIsCAwEAAQ==
    -----END PUBLIC KEY-----
```
2. Add a reference to your secret via the `resources` field in the shoot spec as shown above.
3. Add the name of your referenece in `publicKeysSecretReference` in the provider config as shown above.

Now, whenever Lakom tries to verify a Pod, it will make sure to use your public keys as well.

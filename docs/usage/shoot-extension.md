# Introduction

This extension implements non-keyless [cosign](https://github.com/sigstore/cosign) image signature verification.

## Shoot Feature Gate

Usually the `shoot-lakom-service` extension is enabled globally but also can be configured per shoot cluster.
The example below shows the exposed configuration options, including how to disable the extensions.

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
      trustedKeysResourceName: lakom-ref
...
```

### Scope

The `scope` field instruct lakom which pods to consider for validation.

|Scope|Description|
|-----|-----------|
|`KubeSystem`|Lakom will validate all pods in the `kube-system` namespace.|
|`KubeSystemManagedByGardener`(default)|Lakom will validate all pods in the `kube-system` namespace that are labeled with `resources.gardener.cloud/managed-by=gardener`.|
|`Cluster`|Lakom will validate all pods in all namespaces.|

### TrustedKeysResourceName

Lakom, by default, tries to verify only workloads that belong to Gardener. Because of this, the only public keys that it uses to do its job are the ones for the Gardener workload.

If you'd like to use Lakom as a tool for verifying your own workload, you'll need to add your own public keys to the ones that Lakom is already using. This can be achieved using Gardener [referenced resources](https://github.com/gardener/gardener/blob/master/docs/extensions/referenced-resources.md). More information about the keys and their format can be found [here](lakom.md#lakom-cosign-public-keys-configuration-file).

Simply:

1. Create a secret in your project namespace that contains a field `keys` with your keys as a value. Example keys:

    ```yaml
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

1. Add a reference to your secret via the `resources` field in the shoot spec as shown above.
1. Add the name of your referenece in `trustedKeysResourceName ` in the provider config as shown above.

Now, whenever Lakom tries to verify a Pod, it will make sure to use your public keys as well.

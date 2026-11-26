# Gardener Lakom Service for Shoots

## Introduction

Gardener allows Shoot clusters to use `Lakom` admission controller for cosign image signing verification. To support this the Gardener must be installed with the `shoot-lakom-service` extension.

## Configuration

To generally enable the Lakom service for shoot objects the `shoot-lakom-service` extension must be registered by providing an appropriate [extension registration](../../example/controller-registration.yaml) in the garden cluster.

Here it is possible to decide whether the extension should be always available for all shoots or whether the extension must be separately enabled per shoot.

If the extension should be used for all shoots the `globallyEnabled` flag should be set to `true`.

```yaml
spec:
  resources:
    - kind: Extension
      type: shoot-lakom-service
      globallyEnabled: true
```

Via the ControllerDeployment helm values (field path `.helm.values`), the extension controller behaviour can be additionally configured.
Most of the configuration options are listed in the sample chart [values](../../charts/gardener-extension-shoot-lakom-service/values.yaml) file.
Those affecting the lakom admission controller behaviour in the shoot cluster are:

| Values Field Path | Description | Default Value |
| ---------- | ----------- | ------------- |
| `.controllers.cosignPublicKeys` | The public cosign keys used to verify the OCI image signatures | `{}` |
| `.controllers.useOnlyImagePullSecrets` | Configures lakom admission controller to use only the explicitly configured image pull secrets, otherwise also the node identity and docker config file are used | `true` |
| `.controllers.allowedPrivateRegistryCIDRs` | Private CIDRs permitted for registry, authentication, and redirect requests | `[]` |
| `.controllers.allowUntrustedImages` | Configures lakom admission controllers whether to deny resources using images with untrusted signatures or just to warn about them | `false` |
| `.controllers.allowInsecureRegistries` | Configures lakom admission controllers whether to all communication over `HTTP` with OCI registries, otherwise only `HTTPS` is used | `false` |
| `.controllers.defaultAdmissionScope` | Can be used to overwrite the default Lakom scope of `KubeSystemManagedByGardener` for all shoots | `<unset>` |

### Shoot Feature Gate

If the shoot Lakom service is not globally enabled by default (depends on the extension registration on the garden cluster), it can be enabled per shoot. To enable the service for a shoot, the shoot manifest must explicitly add the `shoot-lakom-service` extension.

```yaml
...
spec:
  extensions:
    - type: shoot-lakom-service
...
```

If the shoot Lakom service is globally enabled by default, it can be disabled per shoot. To disable the service for a shoot, the shoot manifest must explicitly state it.

```yaml
...
spec:
  extensions:
    - type: shoot-lakom-service
      disabled: true
...
```

### Cloud metadata access

When `useOnlyImagePullSecrets: true` is configured, managed Lakom Pods no longer request Gardener's `networking.gardener.cloud/to-blocked-cidrs` egress grant. This removes the additional access used by cloud credential helpers. The extension controller itself does not need this grant either.

This label controls Gardener-generated NetworkPolicies; removing it only restricts traffic where these policies isolate the Pods. Operators of standalone deployments or namespaces without egress isolation must enforce equivalent restrictions through their network configuration.

### Private registries and outbound requests

Registry requests now reject private addresses by default. This applies to image and signature downloads, registry authentication endpoints, and redirect targets. Operators using private registries must configure `allowedPrivateRegistryCIDRs` before upgrading:

```yaml
controllers:
  allowedPrivateRegistryCIDRs:
  - 10.20.30.40/32
  - fd12:3456::1/128
```

These are values for the extension chart. For the standalone chart, use `runtime.allowedPrivateRegistryCIDRs`. In the extension controller configuration, the field is top-level; the Lakom binary accepts `--allowed-private-registry-cidrs`. This is an operator setting shared by the controller's managed instances, not part of a Shoot's extension configuration.

Use the smallest required CIDRs, preferably individual addresses (`/32` or `/128`). Include private authentication and download endpoints as needed. Entries must lie within RFC1918, shared address space (`100.64.0.0/10`), or IPv6 unique-local space (`fc00::/7`). Loopback, link-local, multicast, unspecified addresses, and the metadata endpoint `100.100.100.200` remain blocked even with exceptions.

The registry HTTP transport resolves the hostname, checks every returned address, and connects directly to a checked IP. Each new connection is checked, including connections caused by redirects or authentication challenges. Hostnames remain intact for HTTP Host headers and TLS certificate verification. Registry requests do not use `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`: proxy-side DNS resolution would bypass the destination check. Deployments requiring an HTTP proxy must account for this change before upgrading.

Managed Pods request Gardener's `to-private-networks` egress grant only when private CIDRs are configured. The application transport enforces the individual CIDRs; the Gardener label itself permits the broader private networks defined by Gardener. Existing network policies and routing still apply, so an exception does not itself make a registry reachable. Standalone operators remain responsible for their network policies.

The restriction applies to registry HTTP traffic. Kubernetes API requests and cloud credential-provider SDK requests retain their own transports. Use `useOnlyImagePullSecrets: true` to disable ambient cloud credential providers, and maintain network policies as an additional boundary.

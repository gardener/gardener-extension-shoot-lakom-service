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

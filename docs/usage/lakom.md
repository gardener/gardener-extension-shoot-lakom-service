# Introduction

Lakom is kubernetes admission controller which purpose is to implement
[cosign](https://github.com/sigstore/cosign) image signature verification with
public cosign key. It also takes care to resolve image tags to sha256 digests. A
built-in cache mechanism can be enabled to reduce the load toward the OCI
registry.

## Flags

Lakom admission controller is configurable via command line flags. The trusted
cosign public keys and the associated algorithms associated with them are set
viq configuration file provided with the flag `--lakom-config-path`.

| Flag Name | Description | Default Value |
| ---------- | ----------- | ------------- |
| `--bind-address` | Address to bind to | "0.0.0.0" |
| `--cache-refresh-interval` | Refresh interval for the cached objects | 30s |
| `--cache-ttl` | TTL for the cached objects. Set to 0, if cache has to be disabled | 10m0s |
| `--contention-profiling` | Enable lock contention profiling, if profiling is enabled | false |
| `--health-bind-address` | Bind address for the health server | ":8081" |
| `-h`, `--help` | help for lakom | |
| `--insecure-allow-insecure-registries` | If set, communication via HTTP with registries will be allowed. | false |
| `--insecure-allow-untrusted-images` | If set, the webhook will just return warning for the images without trusted signatures. | false |
| `--kubeconfig` | Paths to a kubeconfig. Only required if out-of-cluster. | |
| `--lakom-config-path` | Path to file with lakom configuration containing cosign public keys used to verify the image signatures | |
| `--metrics-bind-address` | Bind address for the metrics server | ":8080" |
| `--port` | Webhook server port | 9443 |
| `--profiling` | Enable profiling via web interface host:port/debug/pprof/ | false |
| `--tls-cert-dir` | Directory with server TLS certificate and key (must contain a tls.crt and tls.key file | |
| `--use-only-image-pull-secrets` | If set, only the credentials from the image pull secrets of the pod are used to access the OCI registry. Otherwise, the node identity and docker config are also used. | false |
| `--version` | prints version information and quits; --version=vX.Y.Z... sets the reported version | |

## Lakom Cosign Public Keys Configuration File

Lakom cosign public keys configuration file should be YAML or JSON formatted. It
can set multiple trusted keys, as each key must be given a name. The supported
types of public keys are `RSA`, `ECDSA` and `Ed25519`. The `RSA` keys can be
additionally configured with a signature verification algorithm specifying the
scheme and hash function used during signature verification. As of now `ECDSA`
and `Ed25519` keys cannot be configured with specific algorithm.

```yaml
publicKeys:
- name: example-public-key
  algorithm: RSASSA-PSS-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPeQXbIWMMXYV+9+j9b4jXTflnpfwn4E
    GMrmqYVhm0sclXb2FPP5aV/NFH6SZdHDZcT8LCNsNgxzxV4N+UE/JIsCAwEAAQ==
    -----END PUBLIC KEY-----
```

Here:
- `name` can be set to any string.
- `algorithm` needs to be chosen based on the key that you are adding.
- `key` is the key that will be used for validating images using the algorithm that's specified.

### Supported RSA Signature Verification Algorithms

- `RSASSA-PKCS1-v1_5-SHA256`: uses `RSASSA-PKCS1-v1_5` scheme with `SHA256` hash func
- `RSASSA-PKCS1-v1_5-SHA384`: uses `RSASSA-PKCS1-v1_5` scheme with `SHA384` hash func
- `RSASSA-PKCS1-v1_5-SHA512`: uses `RSASSA-PKCS1-v1_5` scheme with `SHA512` hash func
- `RSASSA-PSS-SHA256`: uses `RSASSA-PSS` scheme with `SHA256` hash func
- `RSASSA-PSS-SHA384`: uses `RSASSA-PSS` scheme with `SHA384` hash func
- `RSASSA-PSS-SHA512`: uses `RSASSA-PSS` scheme with `SHA512` hash func

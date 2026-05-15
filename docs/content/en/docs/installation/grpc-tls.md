---
title: "Secure the gRPC API with TLS"
linkTitle: "gRPC TLS / mTLS"
weight: 8
description: "Enable TLS or mTLS on the Tetragon gRPC TCP listener"
---

Tetragon serves its gRPC API on two listeners:

* An always-on **unix-domain socket** at `/var/run/tetragon/tetragon.sock`,
  reserved for in-pod IPC and protected by file permissions.
* An optional **TCP listener** for off-host clients. TLS only applies here.

This page shows how to enable TLS, switch to mTLS, and connect with `tetra`.

{{< note >}}
TLS settings are silently ignored when `--server-address` points at a
`unix://` socket. Configure a TCP address (for example `0.0.0.0:54321`)
before enabling TLS.
{{< /note >}}

## Quick start (Helm, auto-provisioned)

The chart can issue and rotate certificates for you. The default
`auto.method=helm` is the simplest option and requires no extra components.

```shell
helm upgrade --install tetragon cilium/tetragon -n kube-system \
  --set tetragon.grpc.address=0.0.0.0:54321 \
  --set tetragon.grpc.tls.enabled=true
```

The chart generates a CA and a server certificate with a wildcard SAN over
`*.tetragon-grpc.cilium.io`, and writes them to a Secret mounted at
`/var/lib/tetragon/tls/` inside each agent pod. Clients must override SNI to
match this domain (see [Connect with `tetra`](#connect-with-tetra)).

## Enable mTLS

mTLS makes the agent reject TCP connections that do not present a client
certificate signed by the bundled CA.

```shell
helm upgrade --install tetragon cilium/tetragon -n kube-system \
  --set tetragon.grpc.address=0.0.0.0:54321 \
  --set tetragon.grpc.tls.enabled=true \
  --set tetragon.grpc.tls.requireClientCert=true
```

You then mint client certificates from the same CA and pass them to `tetra`
or your own gRPC client.

## Provisioning methods

Pick one method via `tetragon.grpc.tls.auto.method`:

| Method        | When to use                                                                                                                      |
|---------------|----------------------------------------------------------------------------------------------------------------------------------|
| `helm`        | Default. Helm renders the cert/key Secret directly. Rotation requires `helm upgrade`.                                            |
| `cronJob`     | Periodic rotation by `cilium-certgen`. A bootstrap Job seeds the Secret on install; a CronJob refreshes it on `auto.schedule`.   |
| `certmanager` | Hand off issuance to [cert-manager](https://cert-manager.io/). Set `auto.certManagerIssuerRef` to your `Issuer`/`ClusterIssuer`. |

Tunables (`tetragon.grpc.tls.*`) are listed in the
[Helm chart reference]({{< ref "/docs/reference/helm-chart" >}}).

## Bring your own certificates

Disable auto-provisioning and point at an existing Secret:

```shell
helm upgrade --install tetragon cilium/tetragon -n kube-system \
  --set tetragon.grpc.address=0.0.0.0:54321 \
  --set tetragon.grpc.tls.enabled=true \
  --set tetragon.grpc.tls.auto.enabled=false \
  --set tetragon.grpc.tls.server.existingSecret=my-tetragon-grpc-tls
```

The Secret must contain:

* `tls.crt` — PEM server certificate
* `tls.key` — matching PEM private key
* `ca.crt` — PEM CA bundle (required when `requireClientCert=true`)

## Connect with `tetra`

Pass the CA bundle and, for mTLS, the client cert and key. The auto-provisioned
server cert is wildcard, so override SNI to any hostname under
`tetragon-grpc.cilium.io`.

```shell
tetra \
  --server-address tetragon.example.com:54321 \
  --tls-ca-cert-files ca.crt \
  --tls-cert-file client.crt \
  --tls-key-file client.key \
  --tls-server-name node.tetragon-grpc.cilium.io \
  getevents
```

Drop `--tls-cert-file` / `--tls-key-file` if the server is in TLS-only mode.

{{< caution >}}
`--tls-skip-verify` disables server certificate verification and is intended
for local development only. It is mutually exclusive with `--tls-ca-cert-files`.
{{< /caution >}}

## Standalone deployments

For container or systemd installs, set the daemon flags directly through
[drop-in configuration files]({{< ref "/docs/reference/daemon-configuration#configuration-precedence" >}}):

```shell
echo "0.0.0.0:54321"                       > /etc/tetragon/tetragon.conf.d/server-address
echo "/etc/tetragon/tls/tls.crt"           > /etc/tetragon/tetragon.conf.d/server-tls-cert-file
echo "/etc/tetragon/tls/tls.key"           > /etc/tetragon/tetragon.conf.d/server-tls-key-file
# For mTLS, also set:
echo "true"                                > /etc/tetragon/tetragon.conf.d/server-tls-require-client-cert
echo "/etc/tetragon/tls/ca.crt"            > /etc/tetragon/tetragon.conf.d/server-tls-client-ca-files
```

The full flag list is in the
[Daemon configuration reference]({{< ref "/docs/reference/daemon-configuration" >}}).

## Certificate rotation

The agent watches the parent directories of every TLS file with `fsnotify`
and reloads atomically when the contents change. No restart is required when
a Secret or mounted file is updated in place — the next handshake uses the
new material.

## See also

* [Helm chart reference]({{< ref "/docs/reference/helm-chart" >}})
* [Daemon configuration reference]({{< ref "/docs/reference/daemon-configuration" >}})
* [Troubleshooting gRPC TLS]({{< ref "/docs/troubleshooting/grpc-tls" >}})

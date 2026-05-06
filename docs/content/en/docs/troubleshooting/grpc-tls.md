---
title: "Troubleshooting gRPC TLS"
linkTitle: "gRPC TLS"
weight: 4
description: "Common errors when connecting to the Tetragon gRPC API over TLS"
---

The setup steps live in [gRPC TLS / mTLS]({{< ref "/docs/installation/grpc-tls" >}}).
This page covers the three errors operators hit most often.

## `x509: certificate signed by unknown authority`

Seen on the **client** during the TLS handshake.

* **Cause** — `tetra` does not trust the CA that signed the server certificate.
* **Fix** — pass the CA bundle that issued the server cert:

  ```shell
  tetra --tls-ca-cert-files ca.crt ...
  ```

  When the chart auto-provisioned the cert, copy `ca.crt` out of the Secret:

  ```shell
  kubectl -n kube-system get secret tetragon-grpc-server-cert \
    -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
  ```

## `tls: bad certificate`

Seen in the **agent** logs while the client sees `connection closed`.

* **Cause** — the server runs in mTLS mode (`requireClientCert=true`) and the
  client either presented no certificate or one signed by a CA the agent does
  not trust.
* **Fix** — issue a client certificate from the same CA, then pass both halves:

  ```shell
  tetra --tls-cert-file client.crt --tls-key-file client.key ...
  ```

## `x509: certificate is valid for *.tetragon-grpc.cilium.io, not <host>`

Seen on the **client** when the chart auto-provisioned the server cert.

* **Cause** — the auto-issued cert uses a wildcard SAN over a synthetic
  domain, but the dial target is a different hostname or IP.
* **Fix** — override SNI to match the wildcard:

  ```shell
  tetra --tls-server-name node.tetragon-grpc.cilium.io ...
  ```

  To use your own hostnames or IPs instead, add them through
  `tetragon.grpc.tls.server.extraDnsNames` or `extraIpAddresses` and roll out
  the chart.

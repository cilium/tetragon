---
title: "Running Tetragon Operator as Non-Root"
weight: 6
description: "Configure the Tetragon operator to run with non-root privileges"
---

## Running Tetragon Operator as Non-Root

Starting with version X.Y.Z, the Tetragon operator supports running as a non-root user, enhancing the security posture of your Kubernetes deployments.

## Configuration

To run the operator as non-root, configure the following Helm values:

```yaml
tetragonOperator:
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault

  containerSecurityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
      - ALL
```

## Installation

Install Tetragon with non-root operator:

```bash
helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --values non-root-values.yaml
```

## Verification

Verify the operator is running as non-root:

```bash
kubectl exec -n kube-system deployment/tetragon-operator -- id
```

Expected output:

```txt
uid=65532 gid=65532 groups=65532
```

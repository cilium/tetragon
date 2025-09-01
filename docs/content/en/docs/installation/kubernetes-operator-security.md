---
title: "Running Tetragon Operator as Non-Root"
weight: 6
description: "Configure the Tetragon operator to run with non-root privileges"
---

## Running Tetragon Operator as Non-Root

Starting with version 1.6.0, the Tetragon operator runs as a non-root user by
default, enhancing the security posture of your Kubernetes deployments.

## Default Configuration

By default, the Tetragon operator runs with the following security context:

```yaml
tetragonOperator:
  containerSecurityContext:
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - "ALL"
```

## Custom Configuration

To customize the security context, override the `containerSecurityContext`
values:

```yaml
tetragonOperator:
  containerSecurityContext:
    runAsUser: 1001
    runAsGroup: 1001
    runAsNonRoot: true
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - "ALL"
```

## Running as Root (Not Recommended)

If you need to run the operator as root for specific requirements:

```yaml
tetragonOperator:
  containerSecurityContext:
    runAsUser: 0
    runAsGroup: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - "ALL"
```

## Installation

Install Tetragon with custom operator security context:

```bash
helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --values custom-values.yaml
```

## Verification

Verify the operator's security context:

```bash
kubectl get pod -n kube-system -l app.kubernetes.io/name=tetragon-operator\
 -o jsonpath='{.items[0].spec.containers[0].securityContext}' | jq
```

This will show the configured security context for the operator container.

---
title: "Policy tests on Kubernetes"
weight: 9
description: "Run Tetragon policy tests against a Tetragon install on a Kubernetes cluster"
---

Policy tests exercise a `TracingPolicy` end to end: they load the policy, run a
trigger program, and check that the expected events (and any enforcement) are
produced. Locally, `tetra policytest run` does this against an agent on the same
host. On Kubernetes, `tetra policytest run --kube` does the same from inside the
cluster, so you can validate a rule against a real Tetragon install.

## How it works

`tetra policytest run --kube`:

1. Discovers a node running a Ready Tetragon agent.
2. Deploys a short-lived **test pod** on that node, from the policytest image
   (it bundles `tetra` and the trigger programs).
3. The test pod loads the policy as a `TracingPolicyNamespaced` scoped to itself
   with a `podSelector`, runs the trigger, and checks the events — connecting to
   the node-local agent over gRPC.
4. Results are read back from the pod logs; the test pod (and any copied secret)
   is cleaned up.

The policy is constrained to the test pod, so triggers from other workloads do
not pollute the results.

## Prerequisites

- A cluster with Tetragon installed.
- The **policytest image**, available on the target node(s):

  ```shell
  make image-policytest
  # for a kind cluster:
  kind load docker-image cilium/tetragon-policytest:latest --name <cluster>
  ```

- Permissions to manage the test pod and read the agent's TLS secret. A
  least-privilege example is in `examples/policytest/rbac.yaml`.

## Running a test

```shell
tetra policytest run kprobe-lseek --kube \
  --namespace policytest \
  --agent-namespace tetragon
```

Output:

```
P: kprobe-lseek                      ✅   1/1 scenario(s) succeeded
└S: execute lseek and check events   🟢
```

List the available tests with `tetra policytest list`. Useful flags:

- `--namespace` — namespace for the test pod and the namespaced policy.
- `--agent-namespace` — namespace where the Tetragon agent runs.
- `--node` — pin to a specific node (default: any node with a ready agent).
- `--image` — override the policytest image.

## gRPC TLS

A default Helm install serves the gRPC API with **mutual TLS**. `run --kube`
mounts the agent's TLS secret into the test pod and dials with it:

- `--tls-secret` — the `kubernetes.io/tls` secret with the agent's certs
  (default `tetragon-server-certs`). It is copied into the test namespace for
  the duration of the run and removed afterwards. Set it to an empty string for
  a plaintext (non-TLS) agent.
- `--tls-server-name` — SNI / certificate hostname override (default
  `tetragon.local`), needed because the agent is dialed by node IP, which is not
  in the certificate's SANs.

{{< note >}}
Reusing the agent's server certificate as a client certificate works because it
carries the `clientAuth` usage, but it hands the agent's private key to the test
pod. For hardened environments, provision a dedicated client certificate signed
by the agent's CA instead.
{{< /note >}}

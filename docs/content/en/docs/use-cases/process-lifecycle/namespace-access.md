---
title: "Namespace access monitoring"
weight: 4
description: "Monitor namespace changes and detect container escapes"
---

Tetragon can monitor Linux namespace operations to detect when processes change
their namespaces. This is particularly useful for detecting container escapes
where a process attempts to access host namespaces using tools like `nsenter`.

## Use Case: Detecting Container Escapes via Namespace Changes

A common container escape technique involves using `nsenter` to switch into the
host's namespaces. Even if a container is running with restricted privileges,
monitoring `setns` syscalls helps detect attempts to break out of the container's
isolation.

This answers questions like:

> Which processes are attempting to change their Linux namespaces?

> Is there a container escape attempt happening in my cluster?

### Deploying the Demo Application

Before starting, deploy the Demo Application:

```bash
kubectl create -f {{< demo-app-url >}}
```

Verify the pods are running:

```bash
kubectl get pods -A
```

The output should be similar to:

```text
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
default              deathstar-54bb8475cc-6c6lc                   1/1     Running   0          2m54s
default              deathstar-54bb8475cc-zmfkr                   1/1     Running   0          2m54s
default              tiefighter                                   1/1     Running   0          2m54s
default              xwing                                        1/1     Running   0          2m54s
kube-system          tetragon-sdwv6                               2/2     Running   0          27m
```

### Creating the TracingPolicy

To monitor namespace access via the `setns` syscall, we use a TracingPolicy
that hooks into `sys_setns` (this will be transparently resolved to the
architecture specific symbol, `__x64_sys_setns` for x86_64 or `__arm64_sys_setns`
for arm64). This syscall is invoked when a process attempts to change its
namespace.

Create a file named `namespace-access.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "namespace-access"
spec:
  kprobes:
  - call: "sys_setns"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
```

{{< note >}}
The first argument (index 0) is the file descriptor referring to a namespace,
and the second argument (index 1) is a flag specifying the type of namespace.
For more details, see the [setns(2) man page](https://man7.org/linux/man-pages/man2/setns.2.html).
{{< /note >}}

Apply the TracingPolicy:

```bash
kubectl apply -f namespace-access.yaml
```

### Monitoring Namespace Access

Start monitoring events with the `tetra` CLI:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

In another terminal, simulate a container escape attempt by using `nsenter` to
enter the host's namespaces. First, `kubectl exec` into a pod:

```bash
kubectl exec -it xwing -- /bin/bash
```

Then attempt to enter the host namespaces:

```bash
nsenter -t 1 -m -u -n -i -p
```

{{< note >}}
This command attempts to enter the mount (-m), UTS (-u), network (-n), IPC (-i),
and PID (-p) namespaces of PID 1 (the host's init process). In a properly secured
container, this command will fail, but Tetragon will still capture the attempt.
{{< /note >}}

The `tetra` CLI will generate [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}})
events similar to:

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTE2OTc3OTA1NDM0MjAxOjYzMDY2",
      "pid": 63066,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/nsenter",
      "arguments": "-t 1 -m -u -n -i -p",
      "flags": "execve rootcwd clone",
      "start_time": "2026-01-30T18:15:19.985627895Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://057dc8d712abf96c628c82ea111d53a205a256b0dc39bb31284426aaf378acbc",
          "name": "spaceship",
          "image": {
            "id": "quay.io/cilium/json-mock@sha256:5aad04835eda9025fe4561ad31be77fd55309af8158ca8663a72f6abb78c2603",
            "name": "quay.io/cilium/json-mock:latest"
          },
          "start_time": "2026-01-28T08:51:07Z",
          "pid": 37
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing",
        "workload_kind": "Pod"
      },
      "docker": "057dc8d712abf96c628c82ea111d53a",
      "parent_exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTE2OTc3NzI5OTA3MzUxOjYzMDUy",
      "refcnt": 1,
      "tid": 63066
    },
    "parent": {
      "exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTE2OTc3NzI5OTA3MzUxOjYzMDUy",
      "pid": 63052,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2026-01-30T18:15:19.810100966Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://057dc8d712abf96c628c82ea111d53a205a256b0dc39bb31284426aaf378acbc",
          "name": "spaceship",
          "image": {
            "id": "quay.io/cilium/json-mock@sha256:5aad04835eda9025fe4561ad31be77fd55309af8158ca8663a72f6abb78c2603",
            "name": "quay.io/cilium/json-mock:latest"
          },
          "start_time": "2026-01-28T08:51:07Z",
          "pid": 31
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing",
        "workload_kind": "Pod"
      },
      "docker": "057dc8d712abf96c628c82ea111d53a",
      "parent_exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6ODgzNjQ2NzQwMjg6NzIxMQ==",
      "tid": 63052
    },
    "function_name": "__x64_sys_setns",
    "args": [
      {
        "int_arg": 3
      },
      {
        "int_arg": 134217728
      }
    ],
    "action": "KPROBE_ACTION_POST",
    "policy_name": "namespace-access",
    "return_action": "KPROBE_ACTION_POST"
  },
  "node_name": "tetragon-dev-control-plane",
  "time": "2026-01-30T18:15:20.001042828Z"
}
```

{{< note >}}
The second argument (`int_arg: 134217728`) corresponds to `CLONE_NEWIPC` (`0x08000000`), indicating
an attempt to enter the IPC namespace. Other common values include `CLONE_NEWNS` (`0x20000`) for
mount namespace, `CLONE_NEWPID` (`0x20000000`) for PID namespace, and `CLONE_NEWNET` (`0x40000000`)
for network namespace.
{{< /note >}}

### Enforcement: Blocking Namespace Changes

To actively prevent namespace escape attempts, you can extend the policy with a
`Sigkill` action. The following policy will terminate any process that attempts
to call `setns` from within a container:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "deny-namespace-access"
spec:
  kprobes:
  - call: "sys_setns"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    selectors:
    - matchPIDs:
      - operator: NotIn
        followForks: true
        isNamespacePID: true
        values:
        - 0
        - 1
      matchActions:
      - action: Sigkill
```

The `matchPIDs` selector ensures the policy only applies to container processes:
- `isNamespacePID: true`: Uses the PID namespace ID rather than the host PID
- `operator: NotIn` with values `0, 1`: Excludes the init process (PID 1) and
  invalid PIDs, effectively targeting only non-init container processes
- `followForks: true`: Applies the rule to forked child processes as well

{{< caution >}}
Please consult the [Enforcement]({{< ref "/docs/concepts/enforcement" >}}) section
before using enforcement actions in production environments.
{{< /caution >}}

### Cleanup

To remove the TracingPolicy:

```bash
kubectl delete -f namespace-access.yaml
```

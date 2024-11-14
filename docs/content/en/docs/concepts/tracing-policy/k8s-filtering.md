---
title: "Kubernetes Identity Aware Policies"
weight: 4
description: "Tetragon in-kernel filtering based on Kubernetes namespaces, pod labels, and container fields"
---

## Motivation

Tetragon is configured via [TracingPolicies]({{< ref "/docs/concepts/tracing-policy" >}}). Broadly
speaking, TracingPolicies define _what_ situations Tetragon should react to and _how_. The _what_
can be, for example, specific system calls with specific argument values. The _how_ defines what
action the Tetragon agent should perform when the specified situation occurs. The most common action
is generating an event, but there are others (e.g., returning an error without executing the function 
or killing the corresponding process).

Here, we discuss how to apply tracing policies only on a subset of pods running on the system via
the followings mechanisms:
- namespaced policies
- pod-label filters
- container field filters

Tetragon implements these mechanisms in-kernel via eBPF. This is important for both observability
and enforcement use-cases.
For observability, copying only the relevant events from kernel- to user-space reduces overhead. For
enforcement, performing the enforcement action in the kernel avoids the race-condition of doing it
in user-space. For example, let us consider the case where we want to block an application from
performing a system call. Performing the filtering in-kernel means that the application will never
finish executing the system call, which is not possible if enforcement happens in user-space
(after the fact).

To ensure that namespaced tracing policies are always correctly applied, Tetragon needs to perform
actions before containers start executing. Tetragon supports this via [OCI runtime
hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks). If
such hooks are not added, Tetragon will apply policies in a best-effort manner using information
from the k8s API server.

## Namespace filtering

For namespace filtering we use `TracingPolicyNamespaced` which has the same contents as a
`TracingPolicy`, but it is defined in a specific namespace and it is _only_ applied to pods of that
namespace.

## Pod label filters

For pod label filters, we use the `PodSelector` field of tracing policies to select the pods that
the policy is applied to.

## Container field filters

For container field filters, we use the `containerSelector` field of tracing policies to select the containers that the policy is applied to. At the moment, the only supported field is `name`.

## Demo

### Setup

For this demo, we use containerd and configure appropriate run-time hooks using minikube.

First, let us start minikube, build and load images, and install Tetragon and OCI hooks:

```shell
minikube start --container-runtime=containerd
./contrib/tetragon-rthooks/scripts/minikube-install-hook.sh
make image image-operator
minikube image load --daemon=true cilium/tetragon:latest cilium/tetragon-operator:latest
minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf
helm install --namespace kube-system \
	--set tetragonOperator.image.override=cilium/tetragon-operator:latest \
	--set tetragon.image.override=cilium/tetragon:latest  \
	--set tetragon.grpc.address="unix:///var/run/cilium/tetragon/tetragon.sock" \
	tetragon ./install/kubernetes/tetragon
```

Once the tetragon pod is up and running, we can get its name and store it in a variable for convenience.
```shell
tetragon_pod=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o custom-columns=NAME:.metadata.name --no-headers)
```

Once the tetragon operator pod is up and running, we can also get its name and store it in a variable for convenience.
```shell
tetragon_operator=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon-operator -o custom-columns=NAME:.metadata.name --no-headers)
```

Next, we check the tetragon-operator logs and tetragon agent logs to ensure
that everything is in order.

First, we check if the operator installed the TracingPolicyNamespaced CRD.


```shell
kubectl -n kube-system logs -c tetragon-operator $tetragon_operator
```

The expected output is:
```
level=info msg="Tetragon Operator: " subsys=tetragon-operator
level=info msg="CRD (CustomResourceDefinition) is installed and up-to-date" name=TracingPolicy/v1alpha1 subsys=k8s
level=info msg="Creating CRD (CustomResourceDefinition)..." name=TracingPolicyNamespaced/v1alpha1 subsys=k8s
level=info msg="CRD (CustomResourceDefinition) is installed and up-to-date" name=TracingPolicyNamespaced/v1alpha1 subsys=k8s
level=info msg="Initialization complete" subsys=tetragon-operator
```

Next, we check that policyfilter (the low-level mechanism that implements the desired functionality) is indeed enabled.

```shell
kubectl -n kube-system logs -c tetragon $tetragon_pod
```

The output should include:
```
level=info msg="Enabling policy filtering"
```

### Namespaced policies

For illustration purposes, we will use the lseek system call with an invalid
argument. Specifically a file descriptor (the first argument) of -1. Normally,
this operation would return a "Bad file descriptor error".

Let us start a pod in the default namespace:

```shell
kubectl -n default run test --image=python -it --rm --restart=Never  -- python
```

Above command will result in the following python shell:
```
If you don't see a command prompt, try pressing enter.
>>>
```

There is no policy installed, so attempting to do the lseek operation will just
return an error. Using the python shell, we can execute an lseek and see the
returned error.
```
>>> import os
>>> os.lseek(-1,0,0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OSError: [Errno 9] Bad file descriptor
>>>
```

In another terminal, we install a policy in the default namespace:
```shell
cat << EOF | kubectl apply -n default -f -
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "lseek-namespaced"
spec:
  kprobes:
  - call: "sys_lseek"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "-1"
      matchActions:
      - action: Sigkill
EOF
```

The above tracing policy will kill the process that performs a lseek system call with a file
descriptor of `-1`. Note that we use a `SigKill` action only for illustration purposes because it's
easier to observe its effects.

Then, attempting the lseek operation on the previous terminal, will result in the process getting
killed:
```
>>> os.lseek(-1, 0, 0)
pod "test" deleted
pod default/test terminated (Error)
```

The same is true for a newly started container:

```shell
kubectl -n default run test --image=python -it --rm --restart=Never  -- python
```

```
If you don't see a command prompt, try pressing enter.
>>> import os
>>> os.lseek(-1, 0, 0)
pod "test" deleted
pod default/test terminated (Error)
```

Doing the same on another namespace:
```shell
kubectl create namespace test
kubectl -n test run test --image=python -it --rm --restart=Never  -- python
```

Will not kill the process and result in an error:

```
If you don't see a command prompt, try pressing enter.
>>> import os
>>> os.lseek(-1, 0, 0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OSError: [Errno 9] Bad file descriptor
```

### Pod label filters

Let's install a tracing policy with a pod label filter.

```shell
cat << EOF | kubectl apply -f -
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lseek-podfilter"
spec:
  podSelector:
    matchLabels:
      app: "lseek-test"
  kprobes:
  - call: "sys_lseek"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "-1"
      matchActions:
      - action: Sigkill
EOF
```

Pods without the label will not be affected:

```shell
kubectl run test  --image=python -it --rm --restart=Never  -- python
```

```
If you don't see a command prompt, try pressing enter.
>>> import os
>>> os.lseek(-1, 0, 0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  OSError: [Errno 9] Bad file descriptor
  >>>
```

But pods with the label will:
```shell
kubectl run test --labels "app=lseek-test" --image=python -it --rm --restart=Never  -- python
```

```
If you don't see a command prompt, try pressing enter.
>>> import os
>>> os.lseek(-1, 0, 0)
pod "test" deleted
pod default/test terminated (Error)
```

### Container field filters

Let's install a tracing policy with a container field filter.

```shell
cat << EOF | kubectl apply -f -
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lseek-containerfilter"
spec:
  containerSelector:
    matchExpressions:
      - key: name
        operator: In
        values:
        - main
  kprobes:
  - call: "sys_lseek"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "-1"
      matchActions:
      - action: Sigkill
EOF
```

Let's create a pod with 2 containers:

```shell
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: lseek-pod
spec:
  containers:
  - name: main
    image: python
    command: ['sh', '-c', 'sleep infinity']
  - name: sidecar
    image: python
    command: ['sh', '-c', 'sleep infinity']
EOF
```

Containers that don't match the name `main` will not be affected:

```shell
kubectl exec -it lseek-pod -c sidecar -- python3
```

```
>>> import os
>>> os.lseek(-1, 0, 0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  OSError: [Errno 9] Bad file descriptor
>>>
```

But containers matching the name `main` will:
```shell
kubectl exec -it lseek-pod -c main -- python3
```

```
>>> import os
>>> os.lseek(-1, 0, 0)
command terminated with exit code 137
```

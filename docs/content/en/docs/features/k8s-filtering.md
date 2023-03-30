---
title: "K8s Namespace and pod-label filtering"
weight: 1
description: "Tetragon in-kernel filtering using Kubernetes namespaces and pod label filters"
---

## Motivation

Tetragon is configured via [TracingPolicies]({{< ref "docs/reference/tracing-policy" >}}). Broadly speaking,
TracingPolicies define _what_ situations Tetragon should react to and _how_. The
_what_ can be, for example, specific system calls with specific argument
values. The _how_ defines what action the Tetragon agent should perform when
the specified situation occurs.
The most common action is generating and event, but there
are others (e.g., killing the corresponding processes).

Here, we are concerned with applying tracing policies only on a subset of pods
running on the system based on their namespace, and, in future work, their
labels.

To this end, a new type of policy is introduced: `TracingPolicyNamespaced` that
is exactly the same as the existing `TracingPolicy`, but it is _only_ applied
to pods of the namespace that the policy is defined.

As is the case with TracingPolicies, TracingPoliciesNamespaced are
implemented in-kernel with eBPF. This is important for both observability
and enforcement use-cases. For observability, copying only the relevant events
from kernel- to user-space reduces overhead. For enforcement,
performing the enforcement action in-kernel avoids the
race-condition of doing it in user-space. For example, let us consider the case
where we want to block an application from performing a system call. Performing
the filtering in-kernel means that the application will never finish executing
the system call, which is not possible if enforcement happens in user-space.

To ensure that namespaced tracing policies are always correctly applied,
Tetragon needs to perform actions before containers start executing. Tetragon
supports this via [OCI runtime
hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks).
If such hooks are not added, Tetragon will apply policies in a best-effort
manner using information from the k8s API server.


## Demo

For this demo, we use containerd and configure appropriate run-time hooks using minikube.

First, let us start minikube, build and load images, and install Tetragon and OCI hooks:

```shell
minikube start --container-runtime=containerd
./contrib/rthooks/minikube-containerd-install-hook.sh
make image image-operator
minikube image load --daemon=true cilium/tetragon:latest cilium/tetragon-operator:latest
minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf
helm install --namespace kube-system \
	--set tetragonOperator.image.override=cilium/tetragon-operator:latest \
	--set tetragon.image.override=cilium/tetragon:latest  \
	--set tetragon.enablePolicyFilter="true" \
	--set tetragon.grpc.address="unix:///var/run/cilium/tetragon/tetragon.sock" \
	tetragon ./install/kubernetes
```

Once the tetragon pod is up and running, we can get its name.
```shell
tetragon_pod=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o custom-columns=NAME:.metadata.name --no-headers)
```

Next, we check the tetragon-operator logs and tetragon agent logs to ensure
that everything is in order.





First, we check if the operator installed the TracingPolicyNamespaced CRD.


```shell
kubectl -n kube-system logs -c tetragon-operator $tetragon_pod
```

The expected output is:
```
level=info msg="Tetragon Operator: " subsys=tetragon-operator
level=info msg="CRD (CustomResourceDefinition) is installed and up-to-date" name=TracingPolicy/v1alpha1 subsys=k8s
level=info msg="Creating CRD (CustomResourceDefinition)..." name=TracingPolicyNamespaced/v1alpha1 subsys=k8s
level=info msg="CRD (CustomResourceDefinition) is installed and up-to-date" name=TracingPolicyNamespaced/v1alpha1 subsys=k8s
level=info msg="Initialization complete" subsys=tetragon-operator
```

Next, we check that policyfilter (the low level mechanism that implements the desired functionality) is indeed enabled.

```shell
kubectl -n kube-system logs -c tetragon $tetragon_pod
```

The output should include:
```
level=info msg="Enabling policy filtering"
```

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

There is no policy installed so attempting to do the lseek operation will just
return an error. So using the python shell we can execute an lseek and see the
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
  - call: "__x64_sys_lseek"
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
```
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

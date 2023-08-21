---
title: "Example"
icon: "tutorials"
weight: 1
description: "Learn the basics of Tracing Policy via an example"
---


To discover `TracingPolicy`, let's understand via an example that will be
explained, part by part, in this document:

{{< warning >}}
This policy is for illustration purposes only and should not be used to
restrict access to certain files. It can be easily bypassed by, for example,
using hard links.
{{< /warning >}}

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fd-install"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/tetragon"
      matchActions:
      - action: Sigkill
```

## Required fields

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fd-install"
```

The first part follows a common pattern among all Cilium Policies or more
widely [Kubernetes object](https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/).
It first declares the Kubernetes API used, then the kind of Kubernetes object
it is in this API and an arbitrary name for the object, that has to comply with
[Kubernetes naming convention](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/).

## Hook point

```yaml
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
```

The beginning of the specification describe the hook point to use, here we are
using a kprobe, hooking on the kernel function `fd_install`. That's the kernel
function that gets called when a new file descriptor needs to be created. We
indicate that it's not a syscall, but a regular kernel function. Then we
specify the argument of the specified function symbol to be able to extract
them, and optionally perform filtering on them.

See the [hook points page]({{< ref "/docs/concepts/tracing-policy/hooks" >}})
for further information on the various hook points available and arguments.

## Selectors

```yaml
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/tetragon"
      matchActions:
      - action: Sigkill
```

Selectors allow you to filter on the events to extract only a subset of the
events based on different properties and optionally take an enforcement action.

In the example, we filter on the argument at index 1, passing a `file` struct
to the function. Tetragon has the knowledge on how to apply the `Equal`
operator over a Linux kernel `file` struct and you can basically match on the
path of the file.

Then we add the `Sigkill` action, meaning, that any match of the selector
should send a SIGKILL signal to the process that initiated the event.

Learn more about the various selectors in the dedicated
[selectors page]({{< ref "/docs/concepts/tracing-policy/selectors" >}}).

## Policy effect

First, let's create the `/tmp/tetragon` file with some content:
```shell-session
echo eBPF! > /tmp/tetragon
```

Starting Tetragon with the above `TracingPolicy`, for example putting the
policy in the `example.yaml` file, compiling the project locally and starting
Tetragon with (you can do similar things with container image releases, see the
docker run command in the [Try Tetragon on Linux guide]({{< ref
"/docs/getting-started/try-tetragon-linux#observability-with-tracingpolicy" >}}):
```shell-session
sudo ./tetragon --bpf-lib bpf/objs --tracing-policy example.yaml
```

{{< note >}}
Stop tetragon with <kbd>Ctrl</kbd>+<kbd>C</kbd> to disable the policy and
remove the BPF programs.
{{< /note >}}

Reading the `/tmp/tetragon` file with `cat`:
```shell-session
cat /tmp/tetragon
```

Should result in the following events:
```
🚀 process  /usr/bin/cat /tmp/tetragon
📬 open     /usr/bin/cat /tmp/tetragon
💥 exit     /usr/bin/cat /tmp/tetragon SIGKILL
```

And the shell will return:
```
Killed
```

## See more

For more examples of tracing policies, take a look at the
[examples/tracingpolicy](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)
folder in the Tetragon repository. Also read the following sections on
[hook points]({{< ref "/docs/concepts/tracing-policy/hooks" >}}) and
[selectors]({{< ref "/docs/concepts/tracing-policy/selectors" >}}).


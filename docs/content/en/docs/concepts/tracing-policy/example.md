---
title: "Example"
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

The policy checks for file descriptors being created, and sends a `SIGKILL` signal to any process that
creates a file descriptor to a file named `/tmp/tetragon`. We discuss the policy in more detail
next.

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
it is in this API and an arbitrary name for the object that has to comply with
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

The beginning of the specification describes the hook point to use. Here we are
using a kprobe, hooking on the kernel function `fd_install`. That's the kernel
function that gets called when a new file descriptor is created. We
indicate that it's not a syscall, but a regular kernel function. We then
specify the function arguments, so that Tetragon's BPF code will extract
and optionally perform filtering on them.

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
events based on different properties and optionally take an action.

In the example, we filter on the argument at index 1, passing a `file` struct
to the function. Tetragon has the knowledge on how to apply the `Equal`
operator over a Linux kernel `file` struct and match on the
path of the file.

Then we add the `Sigkill` action, meaning, that any match of the selector
should send a SIGKILL signal to the process that initiated the event.

Learn more about the various selectors in the dedicated
[selectors page]({{< ref "/docs/concepts/tracing-policy/selectors" >}}).

## Message

The `message` field is an optional short message that will be included in
the generated event to inform users what is happening.

```yaml
spec:
  kprobes:
  - call: "fd_install"
    message: "Installing a file descriptor"
```

## Tags

Tags are optional fields of a Tracing Policy that are used to categorize generated
events. Further reference here: [Tags documentation]({{< ref "/docs/concepts/tracing-policy/tags" >}}).

## Policy effect

First, let's create the `/tmp/tetragon` file with some content:
```shell
echo eBPF! > /tmp/tetragon
```

You can save the policy in an `example.yaml` file, compile Tetragon locally, and start Tetragon:

```shell
sudo ./tetragon --bpf-lib bpf/objs --tracing-policy example.yaml
```

(See [Quick Kubernetes Install]({{< ref "/docs/getting-started/install-k8s" >}}) and [Quick Local
Docker Install]({{< ref "/docs/getting-started/install-docker" >}}) for other ways to start
Tetragon.)


{{< note >}}
Stop tetragon with <kbd>Ctrl</kbd>+<kbd>C</kbd> to disable the policy and
remove the BPF programs.
{{< /note >}}

Once the Tetragon starts, you can monitor events using `tetra`, the tetragon CLI:
```shell
./tetra getevents -o compact
```

Reading the `/tmp/tetragon` file with `cat`:
```shell
cat /tmp/tetragon
```

Results in the following events:
```
🚀 process  /usr/bin/cat /tmp/tetragon
📬 open     /usr/bin/cat /tmp/tetragon
💥 exit     /usr/bin/cat /tmp/tetragon SIGKILL
```

And the shell where the `cat` command was performed will return:
```
Killed
```

## See more

For more examples of tracing policies, take a look at the
[examples/tracingpolicy](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)
folder in the Tetragon repository. Also read the following sections on
[hook points]({{< ref "/docs/concepts/tracing-policy/hooks" >}}) and
[selectors]({{< ref "/docs/concepts/tracing-policy/selectors" >}}).


---
title: "Tracing Policy"
weight: 1
description: "Reference for the TracingPolicy custom resource"
---

`TracingPolicy` is a user-configurable Kubernetes custom resource (CR) that
allows users to trace arbitrary events in the kernel and optionally define
actions to take on a match, for enforcement for example. Currently, two types
of events are supported: kprobes and tracepoints, but others may be added in
the future (e.g., uprobes) by following a similar approach.

Note that `TracingPolicy` can be considered low-level since they require
knowledge about the Linux kernel and containers to be written correctly. In the
future, we are considering to add a high-level `RuntimeSecurityPolicy` which
would take this complexity away.

For the complete custom resource definition (CRD) refer to the YAML file
[`cilium.io_tracingpolicies.yaml`](https://github.com/cilium/tetragon/blob/main/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml).
One practical way to explore the CRD is to use `kubectl explain` against a
Kubernetes API server on which it is installed, for example `kubectl explain
tracingpolicy.spec.kprobes` provides field-specific documentation and details
on kprobe spec.

For bare metal or VM use cases without Kubernetes, the same YAML configuration
can be passed via a flag to the Tetragon binary (using `--config-file`) or via
the `tetra` CLI to load the policies via gRPC.

### Getting started with Cilium Tracing Policy

To keep the Cilium Policy Definitions unified, the `TracingPolicy` follows the
same CR logic and semantics that you might be familiar with from other Cilium
concepts, like `CiliumNetworkPolicy`.

To discover `TracingPolicy`, let's understand via an example that will be
explained in this document:

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
        - "/etc/passwd"
        - "/etc/shadow"
```

**First required fields**

The first part follows a common pattern among all Cilium Policies or more
widely [Kubernetes object](https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/).
It first declares the Kubernetes API used, then the kind of Kubernetes object
it is in this API and an arbitrary name for the object, that has to comply with
[Kubernetes naming convention](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/).

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fd-install"
```

**The specification**

The `spec` or `specification` can be composed of `kprobes` or `tracepoints` at
the moment. It describes the arbitrary event in the kernel that will be traced.
In our example, we will explore a `kprobe` hooking into the
[`fd_install`](https://elixir.bootlin.com/linux/v6.1.9/source/fs/file.c#L602)
kernel function.

```yaml
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
```

The `fd_install` kernel function is called each time a file descriptor is
installed into the file descriptor table of a process, typically referenced
within system calls like `open` or `openat`. Hooking `fd_install` has its
benefits and limitation, which are out of the scope of this document.

Note the `syscall` field, specific to a `kprobe` spec, that indicates whether
we will be hooking a syscall or just a regular kernel function since they use a
[different ABI](https://gitlab.com/x86-psABIs/x86-64-ABI).

Similarly to other Policies, events can be defined independently in different
policies, or together in the same Policy. For example, we can define trace
multiple kprobes under the same `CiliumTracingPolicy`:
```yaml
spec:
  kprobes:
  - call: "__x64_sys_read"
    syscall: true
    # [...]
  - call: "__x64_sys_write"
    syscall: true
    # [...]
```

### Arguments

A call contains an `args` field which a list of function arguments to include
in the trace output. Indeed the BPF code that runs on the hook point requires
information about the types of arguments of the function being traced to
properly read, print and filter on its arguments. Currently, this information
needs to be provided by the user under the `args` section. For the [available
types](https://github.com/cilium/tetragon/blob/main/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml#L64-L88),
see directly in the `TracingPolicy` CRD.

Following our example, here is the part that defines the arguments:
```yaml
args:
- index: 0
  type: "int"
- index: 1
  type: "file"
```

To properly read and hook onto the `fd_install(unsigned int fd, struct file
*file)` function, the YAML snippet above tells the BPF code that the first
argument is an `int` and the second argument is a `file`, which is the
[`struct file`](https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h#L940)
of the kernel. In this way, the BPF code and its printer can properly collect
and print the arguments.

These types are sorted by the `index` field, where you can specify the order.
The indexing starts with 0. So, `index: 0` means, this is going to be the first
argument of the function, `index: 1` means this is going to be the second
argument of the function, etc.

Note that for some args types, `char_buf` and `char_iovec`, there is an
additional field named `returnCopy` and a `sizeArgIndex` field to specify to
use one of the arguments to read the buffer correctly from the BPF code.

This is the length that the BPF program is looking for in order to read the
`char_buf`. So, `size_t` is the number of `char_buf` elements stored in the
pointer of the second argument. Similarly, if we would like to capture the the
`__x64_sys_writev(long, iovec *, vlen)` syscall, then `iovec` has a size of
`vlen`, which is going to be the 3rd argument.

Please note that `sizeArgIndex` is inconsistent at the moment and does not take
the index, but the number of the index (or index + 1). So if the size is the
third argument, index 2, the value should be 3.

```yaml
- call: "__x64_sys_write"
  syscall: true
  args:
  - index: 0
    type: "int"
  - index: 1
    type: "char_buf"
    returnCopy: true
    sizeArgIndex: 3
  - index: 2
    type: "size_t"
```

Note, that you can specify which arguments you would like to print from a
specific syscall. For example if you don't care about the file descriptor,
which is the first `int` argument with `index: 0` and just want the `char_buf`,
what is written, then you can leave this section out and just define:
```yaml
args:
- index: 1
  type: "char_buf"
  returnCopy: true
  sizeArgIndex: 3
- index: 2
  type: "size_t"
```
This tells the printer to skip printing the `int` arg because it's not useful.

### Selectors

A `TracingPolicy` can contain from 0 to 5 selectors. A selector is composed of
1 or more filters. The available filters are the following:
- [`matchArgs`](#arguments-filter)
- [`matchReturnArgs`](#return-args-filter)
- [`matchPIDs`](#pids-filter)
- [`matchBinaries`](#binaries-filter)
- [`matchNamespaces`](#namespaces-filter)
- [`matchCapabilities`](#capabilities-filter)
- [`matchNamespaceChanges`](#namespace-changes-filter)
- [`matchCapabilityChanges`](#capability-changes-filter)
- [`matchActions`](#actions-filter)

#### Arguments filter

Arguments filters can be specified under the `matchArgs` field and provide
filtering based on the value of the function's argument.

In the next example, a selector is defined with a `matchArgs` filter that tells
the BPF code to process only the function call for which the second argument,
index equal to 1, concerns the file under the path `/etc/passwd` or
`/etc/shadow`. It's using the operator `Equal` to match against the value of
the argument.

Note that conveniently, we can match against a path directly when the argument
is of type `file`.

```yaml
selectors:
- matchArgs:
  - index: 1
    operator: "Equal"
    values:
    - "/etc/passwd"
    - "/etc/shadow"
```

The available operators for `matchArgs` are:
- `Equal`
- `NotEqual`
- `Prefix`
- `Postfix`

**Further examples**

In the previous example, we used the operator `Equal`, but we can also use the
`Prefix` operator and match against all files under `/etc` with:
```yaml
selectors:
- matchArgs:
  - index: 1
    operator: "Prefix"
    values:
    - "/etc"
```
In this situation, an event will be created every time a process tries to
access a file under `/etc`.

Although it makes less sense, you can also match over the first argument, to
only detect events that will use the file descriptor 4, which is usually the
first that come afters stdin, stdout and stderr in process. And combine that
with the previous example.

```yaml
- matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - "3"
  - index: 1
    operator: "Prefix"
    values:
    - "/etc"
```

#### Return args filter

Arguments filters can be specified under the `returnMatchArgs` field and
provide filtering based on the value of the function return value. It allows
you to filter on the return value, thus success, error or value returned by a
kernel call.

```yaml
matchReturnArgs:
- operator: "NotEqual"
  values:
  - 0
```

The available operators for `matchReturnArgs` are:
- `Equal`
- `NotEqual`
- `Prefix`
- `Postfix`

A use case for this would be to detect the failed access to certain files, like
`/etc/shadow`. Doing `cat /etc/shadow` will use a `openat` syscall that will
returns `-1` for a failed attempt with an unprivileged user.

#### PIDs filter

PIDs filters can be specified under the `matchPIDs` field and provide filtering
based on the value of host pid of the process. For example, the following
`matchPIDs` filter tells the BPF code that observe only hooks for which the
host PID is equal to either `pid1` or `pid2` or `pid3`:

```yaml
- matchPIDs:
  - operator: "In"
    followforks: true
    values:
    - "pid1"
    - "pid2"
    - "pid3"
```

The available operators for `matchPIDs` are:
- `In`
- `NotIn`

**Further examples**

Another example can be to collect all processes not associated with a
container's init PID, which is equal to 1. In this way, we are able to detect
if there was a `kubectl exec` performed inside a container because processes
created by `kubectl exec` are not children of PID 1.
```yaml
- matchPIDs:
  - operator: NotIn
    followforks: false
    isNamespacePID: true
    values:
    - 1
```

#### Binaries filter

Binary filters can be specified under the `matchBinaries` field and provide
filtering based on the value of a certain binary name. For example, the
following `matchBinaries` selector tells the BPF code to process only system
calls and kernel functions that are coming from `cat` or `tail`.

```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/cat"
    - "/usr/bin/tail"
```

Currently, only the `In` operator type is supported and the `values` field has
to be a map of `strings`. The default behaviour is `followForks: true`, so all
the child processes are followed. The current limitation is 4 values.

**Further examples**

One example can be to monitor all the `__x64_sys_write` system calls which are
coming from the `/usr/sbin/sshd` binary and its child processes and writing to
`stdin/stdout/stderr`.

This is how we can monitor what was written to the console by different users
during different ssh sessions. The `matchBinaries` selector in this case is the
following:
```yaml
- matchBinarys:
  - operator: "In"
    values:
    - "/usr/sbin/sshd"
```

while the whole `kprobe` call is the following:
```yaml
- call: "__x64_sys_write"
  syscall: true
  args:
  - index: 0
    type: "int"
  - index: 1
    type: "char_buf"
    sizeArgIndex: 3
  - index: 2
    type: "size_t"
  selectors:
  # match to /sbin/sshd
  - matchBinaries:
    - operator: "In"
      values:
      - "/usr/sbin/sshd"
  # match to stdin/stdout/stderr
    matchArgs:
    - index: 0
      operator: "Equal"
      values:
      - "1"
      - "2"
      - "3"
```

#### Namespaces filter

Namespaces filters can be specified under the `matchNamespaces` field and
provide filtering of calls based on Linux namespace. You can specify the
namespace inode or use the special `host_ns` keyword, see the example and
description for more information.

An example syntax is:
```yaml
- matchNamespaces:
  - namespace: Pid
    operator: In
    values:
    - "4026531836"
    - "4026531835"
```

This will match if: [`Pid` namespace is `4026531836`] `OR` [`Pid` namespace is
`4026531835`]

- `namespace` can be: `Uts`, `Ipc`, `Mnt`, `Pid`, `PidForChildren`, `Net`,
  `Cgroup`, or `User`. `Time` and `TimeForChildren` are also available in Linux
  >= 5.6.
- `operator` can be `In` or `NotIn`
- `values` can be raw numeric values (i.e. obtained from `lsns`) or `"host_ns"`
  which will automatically be translated to the appropriate value.

**Limitations**

1. We can have up to 4 `values`. These can be both numeric and `host_ns` inside
   a single `namespace`.
2. We can have up to 4 `namespace` values under `matchNamespaces` in Linux
   kernel < 5.3. In Linux >= 5.3 we can have up to 10 values (i.e. the maximum
   number of namespaces that modern kernels provide).

**Further examples**

We can have multiple namespace filters:
```yaml
selectors:
- matchNamespaces:
  - namespace: Pid
    operator: In
    values:
    - "4026531836"
    - "4026531835"
  - namespace: Mnt
    operator: In
    values:
    - "4026531833"
    - "4026531834"
```
This will match if: ([`Pid` namespace is `4026531836`] `OR` [`Pid` namespace is
`4026531835`]) `AND` ([`Mnt` namespace is `4026531833`] `OR` [`Mnt` namespace
is `4026531834`])


**Use cases examples**

> Generate a kprobe event if `/etc/shadow` was opened by `/bin/cat` which
> either had host `Net` or `Mnt` namespace access

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "example_ns_1"
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: int
        - index: 1
          type: "file"
      selectors:
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

This example has 2 `selectors`. Note that each selector starts with `-`.

Selector 1:
```yaml
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
```
Selector 2:
```yaml
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

We have `[`Selector1 `OR` Selector2`]`. Inside each selector we have `filters`.
Both selectors have 3 filters (i.e. `matchBinaries`, `matchArgs`, and
`matchNamespaces`) with different arguments. Adding a `-` in the beginning of a
filter will result in a new selector.

So the previous CRD will match if:

`[`binary == /bin/cat `AND` arg1 == /etc/shadow `AND` MntNs == host`]` `OR`
`[`binary == /bin/cat `AND` arg1 == /etc/shadow `AND` NetNs is host`]`

We can modify the previous example as follows:

> Generate a kprobe event if `/etc/shadow` was opened by `/bin/cat` which has
> host `Net` and `Mnt` namespace access

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "example_ns_2"
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: int
        - index: 1
          type: "file"
      selectors:
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

Here we have a single selector. This CRD will match if:

`[`binary == /bin/cat `AND` arg1 == /etc/shadow `AND` `(`MntNs == host `AND`
NetNs == host`)` `]`

#### Capabilities filter

Capabilities filters can be specified under the `matchCapabilities` field and
provide filtering of calls based on Linux capabilities in the specific sets.

An example syntax is:
```yaml
- matchCapabilities:
  - type: Effective
    operator: In
    values:
    - "CAP_CHOWN"
    - "CAP_NET_RAW"
```

This will match if: [`Effective` capabilities contain `CAP_CHOWN`] OR
[`Effective` capabilities contain `CAP_NET_RAW`]

- `type` can be: `Effective`, `Inheritable`, or `Permitted`.
- `operator` can be `In` or `NotIn`
- `values` can be any supported capability. A list of all supported
  capabilities can be found in `/usr/include/linux/capability.h`.

**Limitations**

1. There is no limit in the number of capabilities listed under `values`.
2. Only one `type` field can be specified under `matchCapabilities`.

#### Namespace changes filter

Namespace changes filter can be specified under the `matchNamespaceChanges`
field and provide filtering based on calls that are changing Linux namespaces.
This filter can be useful to track execution of code in a new namespace or even
container escapes that change their namespaces.

For instance, if an unprivileged process creates a new user namespace, it gains
full privileges within that namespace. This grants the process the ability to
perform some privileged operations within the context of this new namespace
that would otherwise only be available to privileged root user. As a result, such
filter is useful to track namespace creation, which can be abused by untrusted
processes.

To keep track of the changes, when a `process_exec` happens, the namespaces of
the process are recorded and these are compared with the current namespaces on
the event with a `matchNamespaceChanges` filter.

```yaml
matchNamespaceChanges:
- operator: In
  values:
  - "Mnt"
```

The `unshare` command, or executing in the host namespace using `nsenter` can
be used to test this feature. See a
[demonstration example](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/match_namespace_changes.yaml)
of this feature.

#### Capability changes filter

Capability changes filter can be specified under the `matchCapabilityChanges`
field and provide filtering based on calls that are changing Linux capabilities.

To keep track of the changes, when a `process_exec` happens, the capabilities
of the process are recorded and these are compared with the current
capabilities on the event with a `matchCapabilityChanges` filter.

```yaml
matchCapabilityChanges:
- type: Effective
  operator: In
  isNamespaceCapability: false
  values:
  - "CAP_SETUID"
```

See a [demonstration example](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/match_capability_changes.yaml)
of this feature.

#### Actions filter

Actions filters are a list of actions that execute when an appropriate selector
matches. They are defined under `matchActions` and currently, the following
`action` types are supported:
- [Sigkill action](#sigkill-action)
- [Override action](#override-action)
- [FollowFD action](#followfd-action)
- [UnfollowFD action](#unfollowfd-action)
- [CopyFD action](#copyfd-action)
- [GetUrl action](#geturl-action)
- [DnsLookup action](#dnslookup-action)
- [Post action](#post-action)

Note that `Sigkill`, `Override`, `FollowFD`, `UnfollowFD`, `CopyFD` and `Post`
are executed directly in the kernel BPF code while `GetUrl` and `DnsLookup` are
happening in userspace after the reception of events.

##### Sigkill action

`Sigkill` action terminates synchronously the process that made the call that
matches the appropriate selectors from the kernel. In the example below, every
`__x64_sys_write` system call with a PID not equal to 1 or 0 attempting to
write to `/etc/passwd` will be terminated. Indeed when using `kubectl exec`, a
new process is spawned in the container PID namespace and is not a child of PID
1.

```yaml
- call: "__x64_sys_write"
  syscall: true
  args:
  - index: 0
    type: "fd"
  - index: 1
    type: "char_buf"
    sizeArgIndex: 3
  - index: 2
    type: "size_t"
  selectors:
  - matchPIDs:
    - operator: NotIn
      followForks: true
      isNamespacePID: true
      values:
      - 0
      - 1
    matchArgs:
    - index: 0
      operator: "Prefix"
      values:
      - "/etc/passwd"
    matchActions:
    - action: Sigkill
```

##### Override action

`Override` action allows to modify the return value of call. While `Sigkill`
will terminate the entire process responsible for making the call, `Override`
will override the return value that was supposed to be returned with the value
given in the `argError` field. It's then up to the process handling of the
return value of the function to stop or continue the execution.

For example, you can create a `TracingPolicy` that intercepts `sys_symlinkat`
and will make it return `-1` every time the first argument is equal to the
string `/etc/passwd`:

```yaml
kprobes:
- call: "__x64_sys_symlinkat"
  syscall: true
  args:
  - index: 0
    type: "string"
  - index: 1
    type: "int"
  - index: 2
    type: "string"
  selectors:
  - matchArgs:
    - index: 0
      operator: "Equal"
      values:
      - "/etc/passwd\0"
    matchActions:
    - action: Override
      argError: -1
```

Note that `Override` can override the return value of any call but doing so in
kernel functions can create unexpected code path execution. While syscall are a
stable user interface that should handle errors gracefully.

##### FollowFD action

The `FollowFD` action allows to create a mapping using a BPF map between file
descriptors numbers and filenames. It however needs to maintain a state
correctly, see [`UnfollowFD`](#unfollowfd-action) and
[`CopyFD`](#copyfd-action) related actions.

The `fd_install` kernel function  is called each time a file descriptor must be
installed into the file descriptor table of a process, typically referenced
within system calls like `open` or `openat`. It is a good place for tracking
file descriptor and filename matching.

Let's take a look at the following example:
```yaml
- call: "fd_install"
  syscall: false
  args:
  - index: 0
    type: int
  - index: 1
    type: "file"
  selectors:
  - matchPIDs:
      # [...]
    matchArgs:
      # [...]
    matchActions:
    - action: FollowFD
      argFd: 0
      argName: 1
```

This action uses the dedicated `argFd` and `argName` fields to get respectively
the index of the file descriptor argument and the index of the name argument in
the call.

##### UnfollowFD action

The `UnfollowFD` action takes a file descriptor from a system call and deletes
the corresponding entry from the BPF map, where it was put under the `FollowFD`
action.

Let's take a look at the following example:
```yaml
- call: "__x64_sys_close"
  syscall: true
  args:
  - index: 0
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
    - action: UnfollowFD
      argFd: 0
```

Similar to the `FollowFD` action, the index of the file descriptor is described
under `argFd`:
```yaml
matchActions:
- action: UnfollowFD
  argFd: 0
```

In this example, `argFD` is 0. So, the argument from the `__x64_sys_close`
system call at `index: 0` will be deleted from the BPF map whenever a
`__x64_sys_close` is executed.
```yaml
- index: 0
  type: "int"
```

Note, that whenever we would like to follow a file descriptor with a `FollowFD`
block, there should be a matching `UnfollowFD` block, otherwise the BPF map
will be broken.

##### CopyFD action

The `CopyFD` action is specific to duplication of file descriptor use cases.
Similary to `FollowFD`, it takes an `argFd` and `argName` arguments. It can
typically be used tracking the `dup`, `dup2` or `dup3` syscalls.

See the following example for illustration:

```yaml
- call: "__x64_sys_dup2"
  syscall: true
  args:
  - index: 0
    type: "fd"
  - index: 1
    type: "int"
  selectors:
  - matchPIDs:
    # [...]
    matchActions:
    - action: CopyFD
      argFd: 0
      argName: 1
- call: "__x64_sys_dup3"
  syscall: true
  args:
  - index: 0
    type: "fd"
  - index: 1
    type: "int"
  - index: 2
    type: "int"
  selectors:
  - matchPIDs:
    # [...]
    matchActions:
    - action: CopyFD
      argFd: 0
      argName: 1
```

##### GetUrl action

The `GetUrl` action can be used to perform a remote interaction such as
triggering Thinkst canaries or any system that can be triggered via an URL
request. It uses the `argUrl` field to specify the URL to request using GET
method.

```yaml
matchActions:
- action: GetUrl
  argUrl: http://ebpf.io
```

##### DnsLookup action

The `DnsLookup` action can be used to perform a remote interaction such as
triggering Thinkst canaries or any system that can be triggered via an DNS
entry request. It uses the `argFqdn` field to specify the domain to lookup.

```yaml
matchActions:
- action: DnsLookup
  argFqdn: ebpf.io
```

##### Post action

The `Post` action is intended to create an event but at the moment should be
considered as deprecated as all `TracingPolicy` will generate an event by
default.

### Selector Semantics

The `selector` semantics of the `CiliumTracingPolicy` follows the standard
Kubernetes semantics and the principles that are used by Cilium to create a
unified policy definition.

To explain deeper the structure and the logic behind it, let's consider first
the following example:
```yaml
selectors:
 - matchPIDs:
   - operator: In
     followForks: true
     values:
     - pid1
     - pid2
     - pid3
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - fdString1
```

In the YAML above `matchPIDs` and `matchArgs` are logically `AND` together
giving the expression:
```yaml
(pid in {pid1, pid2, pid3} AND arg0=fdstring1)
```

#### Multiple values

When multiple values are given, we apply the `OR` operation between them. In
case of having multiple values under the `matchPIDs` selector, if any value
matches with the given pid from `pid1`, `pid2` or `pid3` then we accept the
event:
```yaml
pid==pid1 OR pid==pid2 OR pid==pid3
```

As an example, we can filter for `sys_read()` syscalls that were not part of
the container initialization and the main pod process and tried to read from
the `/etc/passwd` file by using:
```yaml
selectors:
 - matchPIDs:
   - operator: NotIn
     followForks: true
     values:
     - 0
     - 1
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - "/etc/passwd"
```

Similarly, we can use multiple values under the `matchArgs` selector:
```yaml
(pid in {pid1, pid2, pid3} AND arg0={fdstring1, fdstring2})
```
If any value matches with `fdstring1` or `fdstring2`, specifically
`(string==fdstring1 OR string==fdstring2)` then we accept the event.

For example, we can monitor `sys_read()` syscalls accessing both the
`/etc/passwd` or the `/etc/shadow` files:
```yaml
selectors:
 - matchPIDs:
   - operator: NotIn
     followForks: true
     values:
     - 0
     - 1
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - "/etc/passwd"
    - "/etc/shadow"
```

#### Multiple operators

When multiple operators are supported under `matchPIDs` or `matchArgs`, they
are logically `AND` together. In case if we have multiple operators under
`matchPIDs`:

```yaml
selectors:
  - matchPIDs:
    - operator: In
      followForks: true
      values:
      - pid1
    - operator: NotIn
      followForks: true
      values:
      - pid2
```
then we would build the following expression on the BPF side:
```yaml
(pid == 0[following forks]) && (pid != 1[following forks])
```

In case of having multiple `matchArgs`:
```yaml
selectors:
 - matchPIDs:
   - operator: In
     followForks: true
     values:
     - pid1
     - pid2
     - pid3
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - 1
  - index: 2
    operator: "lt"
    values:
    - 500
```

Then we would build the following expression on the BPF side
```yaml
(pid in {pid1, pid2, pid3} AND arg0=1 AND arg2 < 500)
```

##### Operator types

There are different types supported for each operator. In case of `matchArgs`:

* Equal
* NotEqual
* Prefix
* Postfix

The operator types `Equal` and `NotEqual` are used to test whether the certain
argument of a system call is equal to the defined value in the CR.

For example, the following YAML snippet matches if the argument at index 0 is
equal to `/etc/passwd`:

```yaml
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
```

Both `Equal` and `NotEqual` are set operations. This means if multiple values
are specified, they are `OR`d together in case of `Equal`, and `AND`d together
in case of `NotEqual`.

For example, in case of `Equal` the following YAML snippet matches if the
argument at index 0 is in the set of `{arg0, arg1, arg2}`.
```yaml
matchArgs:
- index: 0
  operator: "Equal"
  values:
  - "arg0"
  - "arg1"
  - "arg2"
```
The above would be executed in the kernel as
```yaml
arg == arg0 OR arg == arg1 OR arg == arg2
```

In case of `NotEqual` the following YAML snippet matches if the argument at
index 0 is not in the set of `{arg0, arg1}`.
```yaml
matchArgs:
- index: 0
  operator: "NotEqual"
  values:
  - "arg0"
  - "arg1"
```
The above would be executed in the kernel as
```yaml
arg != arg0 AND arg != arg1
```

The type `Prefix` checks if the certain argument starts with the defined value,
while the type `Postfix` compares if the argument matches to the defined value
as trailing.

In case of `matchPIDs`:

* In
* NotIn

The operator types `In` and `NotIn` are used to test whether the pid of a
system call is found in the provided `values` list in the CR. Both `In` and
`NotIn` are set operations, which means if multiple values are specified they
are `OR`d together in case of `In` and `AND`d together in case of `NotIn`.

For example, in case of `In` the following YAML snippet matches if the pid of a
certain system call is being part of the list of `{0, 1}`:
```yaml
- matchPIDs:
  - operator: In
    followForks: true
    isNamespacePID: true
    values:
    - 0
    - 1
```
The above would be executed in the kernel as
```yaml
pid == 0 OR pid == 1
```

In case of `NotIn` the following YAML snippet matches if the pid of a certain
system call is not being part of the list of `{0, 1}`:
```yaml
- matchPIDs:
  - operator: NotIn
    followForks: true
    isNamespacePID: true
    values:
    - 0
    - 1
```
The above would be executed in the kernel as
```yaml
pid != 0 AND pid != 1
```

In case of `matchBinaries`:

* In

The `In` operator type is used to test whether a binary name of a system call
is found in the provided `values` list. For example, the following YAML snippet
matches if the binary name of a certain system call is being part of the list
of `{binary0, binary1, binary2}`:

```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "binary0"
    - "binary1"
    - "binary2"
```

#### Multiple selectors

When multiple selectors are configured they are logically `OR`d together.
```yaml
selectors:
 - matchPIDs:
   - operator: In
     followForks: true
     values:
     - pid1
     - pid2
     - pid3
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - 1
  - index: 2
    operator: "lt"
    values:
    -  500
 - matchPIDs:
   - operator: In
     followForks: true
     values:
     - pid1
     - pid2
     - pid3
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - 2
```

The above would be executed in kernel as:
```yaml
(pid in {pid1, pid2, pid3} AND arg0=1 AND arg2 < 500) OR
(pid in {pid1, pid2, pid3} AND arg0=2)
```

##### Limitations

Because BPF must be bounded we have to place limits on how many selectors can
exist.

- Max Selectors 8.
- Max PID values per selector 4
- Max MatchArgs per selector 5 (one per index)
- Max MatchArg Values per MatchArgs 1 (limiting initial implementation can bump
  to 16 or so)

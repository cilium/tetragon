---
title: "Selectors"
weight: 3
description: "Perform in-kernel BPF filtering and actions on events"
---

Selectors are a way to perform in-kernel BPF filtering on the events to
export, or on the events on which to apply an action.

A `TracingPolicy` can contain from 0 to 5 selectors. A selector is composed of
1 or more filters. The available filters are the following:
- [`matchArgs`](#arguments-filter): filter on the value of arguments.
- [`matchReturnArgs`](#return-args-filter): filter on the return value.
- [`matchPIDs`](#pids-filter): filter on PID.
- [`matchBinaries`](#binaries-filter): filter on binary path.
- [`matchNamespaces`](#namespaces-filter): filter on Linux namespaces.
- [`matchCapabilities`](#capabilities-filter): filter on Linux capabilities.
- [`matchNamespaceChanges`](#namespace-changes-filter): filter on Linux namespaces changes.
- [`matchCapabilityChanges`](#capability-changes-filter): filter on Linux capabilities changes.
- [`matchActions`](#actions-filter): apply an action on selector matching.
- [`matchReturnActions`](#return-actions-filter): apply an action on return selector matching.

## Arguments filter

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
- `Mask`

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

## Return args filter

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

## PIDs filter

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

## Binaries filter

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

One example can be to monitor all the `sys_write` system calls which are
coming from the `/usr/sbin/sshd` binary and its child processes and writing to
`stdin/stdout/stderr`.

This is how we can monitor what was written to the console by different users
during different ssh sessions. The `matchBinaries` selector in this case is the
following:
```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/sbin/sshd"
```

while the whole `kprobe` call is the following:
```yaml
- call: "sys_write"
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

## Namespaces filter

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
  \>= 5.6.
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

## Capabilities filter

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

## Namespace changes filter

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

## Capability changes filter

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

## Actions filter

Actions filters are a list of actions that execute when an appropriate selector
matches. They are defined under `matchActions` and currently, the following
`action` types are supported:
- [Sigkill action](#sigkill-action)
- [Signal action](#signal-action)
- [Override action](#override-action)
- [FollowFD action](#followfd-action)
- [UnfollowFD action](#unfollowfd-action)
- [CopyFD action](#copyfd-action)
- [GetUrl action](#geturl-action)
- [DnsLookup action](#dnslookup-action)
- [Post action](#post-action)
- [NoPost action](#nopost-action)
- [TrackSock action](#tracksock-action)
- [UntrackSock action](#untracksock-action)
- [Notify Killer action](#notify-killer-action)

{{< note >}}
`Sigkill`, `Override`, `FollowFD`, `UnfollowFD`, `CopyFD`, `Post`,
`TrackSock` and `UntrackSock` are
executed directly in the kernel BPF code while `GetUrl` and `DnsLookup` are
happening in userspace after the reception of events.
{{< /note >}}

### Sigkill action

`Sigkill` action terminates synchronously the process that made the call that
matches the appropriate selectors from the kernel. In the example below, every
`sys_write` system call with a PID not equal to 1 or 0 attempting to write to
`/etc/passwd` will be terminated. Indeed when using `kubectl exec`, a new
process is spawned in the container PID namespace and is not a child of PID 1.

```yaml
- call: "sys_write"
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

{{< caution >}}
Please consult the [Enforcement]({{<ref "/docs/concepts/enforcement" >}}) section if you plan to use
this action for enforcement.
{{< /caution >}}

### Signal action

`Signal` action sends specified signal to current process. The signal number
is specified with `argSig` value.

Following example is equivalent to the Sigkill action example above.
The difference is to use the signal action with `SIGKILL(9)` signal.

```yaml
- call: "sys_write"
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
    - action: Signal
      argSig: 9
```

{{< caution >}}
Please consult the [Enforcement]({{<ref "/docs/concepts/enforcement" >}}) section if you plan to use
this action for enforcement.
{{< /caution >}}


### Override action

`Override` action allows to modify the return value of call. While `Sigkill`
will terminate the entire process responsible for making the call, `Override`
will run in place of the original kprobed function and return the value
specified in the `argError` field. It's then up to the code path or the user
space process handling the returned value to whether stop or proceed with the
execution.

For example, you can create a `TracingPolicy` that intercepts `sys_symlinkat`
and will make it return `-1` every time the first argument is equal to the
string `/etc/passwd`:

```yaml
kprobes:
- call: "sys_symlinkat"
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

{{< note >}}
`Override` uses the kernel error injection framework and is only available
on kernels compiled with `CONFIG_BPF_KPROBE_OVERRIDE` configuration option.

Overriding system calls is the primary use case, but there are other kernel
functions that support error injections too. These functions are annotated
with `ALLOW_ERROR_INJECTION()` in the kernel source, and can be identified by
reading the file `/sys/kernel/debug/error_injection/list`.

Starting from kernel version `5.7` overriding `security_` hooks is also possible.
{{< /note >}}

{{< caution >}}
For kernel developers: if you want to override your kernel functions then
ensure they properly follow the [Error Injectable Functions](https://docs.kernel.org/fault-injection/fault-injection.html#error-injectable-functions) guide.
{{< /caution >}}

### FollowFD action

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

### UnfollowFD action

The `UnfollowFD` action takes a file descriptor from a system call and deletes
the corresponding entry from the BPF map, where it was put under the `FollowFD`
action.

Let's take a look at the following example:
```yaml
- call: "sys_close"
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

In this example, `argFD` is 0. So, the argument from the `sys_close` system
call at `index: 0` will be deleted from the BPF map whenever a `sys_close` is
executed.
```yaml
- index: 0
  type: "int"
```

{{< caution >}}
Whenever we would like to follow a file descriptor with a `FollowFD` block,
there should be a matching `UnfollowFD` block, otherwise the BPF map will be
broken.
{{< /caution >}}

### CopyFD action

The `CopyFD` action is specific to duplication of file descriptor use cases.
Similary to `FollowFD`, it takes an `argFd` and `argName` arguments. It can
typically be used tracking the `dup`, `dup2` or `dup3` syscalls.

See the following example for illustration:

```yaml
- call: "sys_dup2"
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
- call: "sys_dup3"
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

### GetUrl action

The `GetUrl` action can be used to perform a remote interaction such as
triggering Thinkst canaries or any system that can be triggered via an URL
request. It uses the `argUrl` field to specify the URL to request using GET
method.

```yaml
matchActions:
- action: GetUrl
  argUrl: http://ebpf.io
```

### DnsLookup action

The `DnsLookup` action can be used to perform a remote interaction such as
triggering Thinkst canaries or any system that can be triggered via an DNS
entry request. It uses the `argFqdn` field to specify the domain to lookup.

```yaml
matchActions:
- action: DnsLookup
  argFqdn: ebpf.io
```

### Post action

The `Post` action allows an event to be transmitted to the agent, from
kernelspace to userspace. By default, all `TracingPolicy` hook will create an
event with the `Post` action except in those situations:
- a `NoPost` action was specified in a `matchActions`;
- a rate-limiting parameter is in place, see details below.

This action allows you to specify parameters for the `Post` action.

#### Rate limiting

`Post` takes the `rateLimit` parameter with a time value. This value defaults
to seconds, but post-fixing 'm' or 'h' will cause the value to be interpreted
in minutes or hours. When this parameter is specified for an action, that
action will check if the same action has fired, for the same thread, within
the time window, with the same inspected arguments. (Only the first 40 bytes
of each inspected argument is used in the matching. Only supported on kernels
v5.3 onwards.)

For example, you can specify a selector to only generate an event every 5
minutes with adding the following action and its paramater:

```yaml
matchActions:
- action: Post
  rateLimit: 5m
```

By default, the rate limiting is applied per thread, meaning that only repeated
actions by the same thread will be rate limited. This can be expanded to all
threads for a process by specifying a rateLimitScope with value "process"; or
can be expanded to all processes by specifying the same with the value "global".

#### Stack traces

`Post` takes the `stackTrace` parameter, when turned to `true` (by default to
`false`) it enables dump of the kernel stack trace to the hook point in kprobes
events. For example, the following kprobe hook can be used to retrieve the
kernel stack to `kfree_skb_reason`, the function called in the kernel to drop
kernel socket buffers.

```yaml
kprobes:
  - call: kfree_skb_reason
    selectors:
    - matchActions:
      - action: post
        stackTrace: true
```

{{< caution >}}
By default Tetragon does not expose the kernel addresses, you need to enable
the flag `--expose-kernel-addresses` to get the addresses along the rest.

Note that the Tetragon agent is using its privilege to read the kernel symbols
and their address. Being able to retrieve kernel symbols address can be used to
break kernel address space layout randomization (KASLR) so only privileged users
should be able to enable this feature and read events containing stack traces.
{{< /caution >}}

Once loaded, events created from this policy will contain a new `stack_trace`
field on the `process_kprobe` event with an output similar to:

```
{
  "address": "18446670264256120896",
  "offset": "272",
  "symbol": "skb_release_head_state"
},
{
  "address": "18446670264257081512",
  "offset": "88",
  "symbol": "ip_protocol_deliver_rcu"
},
{
  "address": "18446670264257082152",
  "offset": "88",
  "symbol": "ip_local_deliver_finish"
},
[...]
```

The "address" is the kernel function address, "offset" is the offset into the
native instruction for the function and "symbol" is the function symbol name.

This output can be enhanced in a more human friendly using the `tetra getevents
-o compact` command. Indeed, by default, it will print the stack trace along
the compact output of the event similarly to this:

```
❓ syscall  /usr/bin/curl kfree_skb_reason
   0xffffbcdee5bf4840: skb_release_head_state+0x110
   0xffffbcdee5be3678: __sys_connect_file+0x88
   0xffffbcdee5be376c: __sys_connect+0xbc
   0xffffbcdee5be37bc: __arm64_sys_connect+0x28
   0xffffbcdee4dfcd68: invoke_syscall+0x78
   0xffffbcdee4dfcf70: el0_svc_common.constprop.0+0x180
   0xffffbcdee4dfcfa4: do_el0_svc+0x30
   0xffffbcdee5e861e8: el0_svc+0x48
   0xffffbcdee5e881b4: el0t_64_sync_handler+0xa4
   0xffffbcdee4de1e38: el0t_64_sync+0x1a4
```

The printing format is `"0x%x: %s+0x%x", address, symbol, offset`.

{{< note >}}
Compact output will display missing addresses as `0x0`, see the above note on
`--expose-kernel-addresses` for more info.
{{< /note >}}

### NoPost action

The `NoPost` action can be used to suppress the event to be generated, but at
the same time all its defined actions are performed.

It's useful when you are not interested in the event itself, just in the action
being performed.

Following example override openat syscall for "/etc/passwd" file but does not
generate any event about that.


```yaml
- call: "sys_openat"
  return: true
  syscall: true
  args:
  - index: 0
    type: int
  - index: 1
    type: "string"
  - index: 2
    type: "int"
  returnArg:
    type: "int"
  selectors:
  - matchPIDs:
    matchArgs:
    - index: 1
      operator: "Equal"
      values:
      - "/etc/passwd"
    matchActions:
    - action: Override
      argError: -2
    - action: NoPost
```

### TrackSock action

The `TrackSock` action allows to create a mapping using a BPF map between sockets
and processes. It however needs to maintain a state
correctly, see [`UntrackSock`](#untracksock-action) related action. `TrackSock`
works similarly to `FollowFD`, specifying the argument with the `sock` type using
`argSock` instead of specifying the FD argument with `argFd`.

It is however more likely that socket tracking will be performed on the return
value of `sk_alloc` as described above.

Socket tracking is only available on kernel >=5.3.

### UntrackSock action

The `UntrackSock` action takes a struct sock pointer from a function call and deletes
the corresponding entry from the BPF map, where it was put under the `TrackSock`
action.

Let's take a look at the following example:
```yaml
- call: "__sk_free"
  syscall: false
  args:
    - index: 0
      type: sock
  selectors:
    - matchActions:
      - action: UntrackSock
        argSock: 0
```

Similar to the `TrackSock` action, the index of the sock is described under `argSock`:
```yaml
- matchActions:
  - action: UntrackSock
    argSock: 0
```

In this example, `argSock` is 0. So, the argument from the `__sk_free` function
call at `index: 0` will be deleted from the BPF map whenever a `__sk_free` is
executed.
```yaml
- index: 0
  type: "sock"
```

{{< caution >}}
Whenever we would like to track a socket with a `TrackSock` block,
there should be a matching `UntrackSock` block, otherwise the BPF map will be
broken.
{{< /caution >}}

Socket tracking is only available on kernel >=5.3.

### Notify Killer action

The `NotifyKiller` action notifies the killer program to kill or override a syscall.

It's meant to be used on systems with kernel that lacks multi kprobe feature, that
allows to attach many kprobes quickly). To workaround that the killer sensor uses
the raw syscall tracepoint and attaches simple program to syscalls that we need to
kill or override.

The specs needs to have `killer` program definition, that instructs tetragon to load
the `killer` program and attach it to specified syscalls.

```yaml
spec:
  killers:
  - syscalls:
    - "list:dups"
```

The syscalls expects list of syscalls or `list:XXX` pointer to list.

Note that currently only single killer definition is allowed.


The `NotifyKiller` action takes 2 arguments.

```yaml
matchActions:
- action: "NotifyKiller"
  argError: -1
  argSig: 9
```

If specified the argError will be passed to `bpf_override_return` helper to override the syscall return value.
If specified the argSig will be passed to `bpf_send_signal` helper to override the syscall return value.

The following is spec for killing `/usr/bin/bash` program whenever it calls `sys_dup` or `sys_dup2` syscalls.

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
  killers:
  - syscalls:
    - "list:dups"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:dups"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
      matchActions:
      - action: "NotifyKiller"
        argSig: 9
```

Note as mentioned above the `NotifyKiller` with killer program is meant to be used only on kernel versions
with no support for fast attach of multiple kprobes (`kprobe_multi` link).

With `kprobe_multi` link support the above example can be easily replaced with:

```yaml
spec:
  lists:
  - name: "syscalls"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
  kprobes:
  - call: "list:syscalls"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
      matchActions:
      - action: "Sigkill"
```

## Selector Semantics

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

### Multiple values

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

### Multiple operators

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

#### Operator types

There are different types supported for each operator. In case of `matchArgs`:

* Equal
* NotEqual
* Prefix
* Postfix
* Mask
* GreaterThan (aka GT)
* LessThan (aka LT)
* SPort - Source Port
* NotSPort - Not Source Port
* SPortPriv - Source Port is Privileged (0-1023)
* NotSPortPriv - Source Port is Not Privileged (Not 0-1023)
* DPort - Destination Port
* NotDPort - Not Destination Port
* DPortPriv - Destination Port is Privileged (0-1023)
* NotDPortPriv - Destination Port is Not Privileged (Not 0-1023)
* SAddr - Source Address, can be IPv4/6 address or IPv4/6 CIDR (for ex 1.2.3.4/24 or 2a1:56::1/128)
* NotSAddr - Not Source Address
* DAddr - Destination Address
* NotDAddr - Not Destination Address
* Protocol
* Family
* State

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

The operator type `Mask` performs and bitwise operation on the argument value
and defined values. The argument type needs to be one of the value types.

For example in following YAML snippet we match second argument for bits
1 and 9 (0x200 value). We could use single value 0x201 as well.

```yaml
matchArgs:
- index: 2
  operator: "Mask"
  values:
  - 1
  - 0x200
```

The above would be executed in the kernel as
```yaml
arg & 1 OR arg & 0x200
```

The value can be specified as hexadecimal (with 0x prefix) octal (with 0 prefix)
or decimal value (no prefix).

The operator `Prefix` checks if the certain argument starts with the defined value,
while the operator `Postfix` compares if the argument matches to the defined value
as trailing.

The operators relating to ports, addresses and protocol are used with sock or skb
types. Port operators can accept a range of ports specified as `min:max` as well
as lists of individual ports. Address operators can accept IPv4/6 CIDR ranges as well
as lists of individual addresses.

The `Protocol` operator can accept integer values to match against, or the equivalent
IPPROTO_ enumeration. For example, UDP can be specified as either `IPPROTO_UDP` or 17;
TCP can be specified as either `IPPROTO_TCP` or 6.

The `Family` operator can accept integer values to match against or the equivalent
AF_ enumeration. For example, IPv4 can be specified as either `AF_INET` or 2; IPv6
can be specified as either `AF_INET6` or 10.

The `State` operator can accept integer values to match against or the equivalent
TCP_ enumeration. For example, an established socket can be matched with
`TCP_ESTABLISHED` or 1; a closed socket with `TCP_CLOSE` or 7.

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

### Multiple selectors

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

### Limitations

{{% pageinfo %}}
Those limitations might be outdated, see [issue #709](https://github.com/cilium/tetragon/issues/709).
{{% /pageinfo %}}

Because BPF must be bounded we have to place limits on how many selectors can
exist.

- Max Selectors 8.
- Max PID values per selector 4
- Max MatchArgs per selector 5 (one per index)
- Max MatchArg Values per MatchArgs 1 (limiting initial implementation can bump
  to 16 or so)


## Return Actions filter

Return actions filters are a list of actions that execute when an return selector
matches. They are defined under `matchReturnActions` and currently support all
the [Actions filter](#actions-filter) `action` types.

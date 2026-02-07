---
title: "Selectors"
weight: 3
description: "Perform in-kernel BPF filtering and actions on events"
---

Selectors enable per-hook in-kernel BPF filtering and actions. Each selector defines a set of
filters as well as a set of (optional) actions to be performed if the selector filters match. Each
hook can contain up to 5 selectors. If no selectors are defined on a hook, the default action
(`Post`, i.e., post an event) will be used.


Each selector comprises a set of filters:
- [`matchArgs`](#arguments-filter): filter on the value of arguments.
- [`matchData`](#data-filter): filter on the value of data fields.
- [`matchReturnArgs`](#return-args-filter): filter on the return value.
- [`matchPIDs`](#pids-filter): filter on PID.
- [`matchBinaries`](#binaries-filter): filter on binary path.
- [`matchParentBinaries`](#parent-binaries-filter): filter on parent binary path.
- [`matchNamespaces`](#namespaces-filter): filter on Linux namespaces.
- [`matchCapabilities`](#capabilities-filter): filter on Linux capabilities.
- [`matchNamespaceChanges`](#namespace-changes-filter): filter on Linux namespaces changes.
- [`matchCapabilityChanges`](#capability-changes-filter): filter on Linux capabilities changes.

And a set of actions that will be performed if the specified filters match:
- [`matchActions`](#actions-filter): apply an action on selector matching.
- [`matchReturnActions`](#return-actions-filter): apply an action on return selector matching.

For a selector to match, all of its filters must match (AND operator). If a selector defines no
filters, it matches. If multiple selectors are defined in a hook, only the action defined in the
first matching selector will be applied (short-circuited OR). If a selector defines no action, the
default action (`Post`) is applied.

For example, the following policy will generate events when the `sys_mount` system call is executed
by binaries other than `/usr/bin/mount`.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "mount-example"
spec:
  kprobes:
  - call: "sys_mount"
    syscall: true
    selectors:
      # first selector
      - matchBinaries:
        - operator: In
          values:
          - "/usr/bin/mount"
        matchActions:
        - action: NoPost
      # second selector
      - matchActions:
        - action: Post

```

## Arguments filter

Arguments filters can be specified under the `matchArgs` field and provide
filtering based on the value of the function's argument.

You can specify the argument either in the `index` or in `args` field. The `index` field
denotes the argument position within the function arguments, while the  `args`
field denotes the arguments position within the spec arguments. Both fields are
zero based (1st argument has zero value). The `args` field (if defined) takes
precedence over `index` field.

The `args` field can support multiple arguments. Currently, the only operator that supports more
than 1 argument is the `CapabilitiesGained` operator.

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
In the next example, a selector is defined with a `matchArgs` filter that tells
the BPF code to process only the function call for which the second spec argument,
`args` equals to [1] (which represents 1st function argument, `index` equals to 0),
has value `0xcoffee`.

```yaml
- args:
  - index: 2
    type: "int"
    label: "arg0-index2"
  - index: 0
    type: "int"
    label: "arg1-index1"
  - index: 1
    type: "int"
    label: "arg2-index0"
  selectors:
  - matchArgs:
    - args: [1]
      operator: "Equal"
      values:
      - "0xcoffee"
```
Note that you can mix `index` and `arg` fields within `matchArgs` selector definitions.

The available operators for `matchArgs` are:
- `Equal`
- `NotEqual`
- `Prefix`
- `Postfix`
- `Mask`
- `FileType`
- `NotFileType`

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

### File type filtering

The `FileType` and `NotFileType` operators allow filtering based on the type of a
file (e.g., regular file, pipe, socket, etc.). These operators can only be used
with arguments of type `file` or `path`.

Matching file types:
- `sock` or `socket`: Socket
- `lnk` or `link`: Symbolic link
- `reg` or `regular`: Regular file
- `blk` or `block`: Block device
- `dir`: Directory
- `chr` or `char`: Character device
- `fifo` or `pipe`: FIFO/Pipe

In the following example, we monitor `vfs_write` only for regular files.

```yaml
selectors:
- matchArgs:
  - index: 0
    operator: "FileType"
    values:
    - "reg"
```

## Data filter

Data filters can be specified under the `matchData` field and provide
filtering based on the value of the specified `data` field.

You can specify the argument either in the `index` or in `args` field. Both `index` and
`args` field denote the argument position within the spec file.

In the following example we extra pid value from `current_task` and filter
on all values except for `1`.

```yaml
data:
- type: "string"
  source: "current_task"
  resolve: "pid"
selectors:
- matchData:
  - index: 0
    operator: "NotEqual"
    values:
    - "1"
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
    followForks: true
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
    followForks: false
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

The available operators for `matchBinaries` are:
- `In`
- `NotIn`
- `Prefix`
- `NotPrefix`
- `Postfix`
- `NotPostfix`

The `values` field has to be a map of `strings`. The default behaviour
is `followForks: true`, so all the child processes are followed.

### Follow children

The `matchBinaries` filter can be configured to also apply to children of matching processes. To do
this, set `followChildren` to `true`. For example:

```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/sbin/sshd"
    followChildren: true
```

There are a number of limitations when using followChildren:
- Children created before the policy was installed will not be matched.
- The number of `matchBinaries` sections with `followChildren: true` cannot exceed 64.
- `operator` can be `In` or `NotIn`.


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
    followChildren: true
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
      followChildren: true
  # match to stdin/stdout/stderr
    matchArgs:
    - index: 0
      operator: "Equal"
      values:
      - "1"
      - "2"
      - "3"
```


### Scripts with shebangs

{{< caution >}}
`matchBinaries` matches against the `interpreter`, not the script path.
{{< /caution >}}

When executing a script with a shebang (i.e. `#!/usr/bin/python3`), Linux actually runs the
interpreter and passes the script as an argument. Current implementation of `matchBinaries` filters based on the interpreter path (i.e. `/usr/bin/python3`) and not the script name (i.e. `/opt/scripts/my_script.py`).

This won't work:

```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "/opt/scripts/my_script.py"
```

Match the interpreter instead:

```yaml
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/python3"
```

## Parent binaries filter

{{< warning >}}
`matchParentBinaries` selector can be used only with BPF map `parents_map` enabled (option `--parents-map-enabled`), which adds
additional memory overhead. 
{{< /warning >}}

Parent binaries filter provides filtering based on current process parent
binary path, which works similarly to the `matchBinaries` filter. It can be
specified with the `matchParentBinaries` field. For instance, the following
`matchParentBinaries` selector will match only if binary `cat` was executed
from interactive shell like `zsh`, `bash`, `sh`:

```yaml
- matchParentBinaries:
  - operator: "In"
    values:
    - "/usr/bin/bash"
    - "/usr/bin/sh"
    - "/usr/bin/zsh"
  matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/cat"
```

The available operators for `matchParentBinaries` are:
- `In`
- `NotIn`
- `Prefix`
- `NotPrefix`
- `Postfix`
- `NotPostfix`

The `values` field has to be a map of `strings`. The default behaviour
is `followForks: true`, so all the child processes are followed.

### Follow children

The `matchParentBinaries` filter can be configured to also apply to children of
matching parent processes. To do this, set `followChildren` to `true`. For example:

```yaml
- matchParentBinaries:
  - operator: "In"
    values:
    - "/usr/bin/bash"
    followChildren: true
```

This policy will match any process, which direct or transitive parent process binary is `bash`.

There are a number of limitations when using `followChildren`:
- Children created before the policy was installed will not be matched.
- The number of `matchParentBinaries` sections with `followChildren: true` cannot exceed 64.
- Operators other than `In/NotIn` are not supported.

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
be used to test this feature.

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

See a [demonstration example](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/fd_install_cap_changes.yaml)
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
- [Notify Enforcer action](#notify-enforcer-action)
- [USDT Set action](#usdt-set-action)

{{< warning >}}
The FollowFD and related (UnfollowFD, CopyFD) actions have been deprecated due to being unsafe and
are planned to be removed in version 1.5.
{{< /warning >}}

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

Override action is defined for kprobe and uprobe selectors.

#### Override action for kprobe

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

#### Override action for uprobe

{{< warning >}}
Beware, here be dragons!!! Use with caution, it could easily crash traced application.
{{< /warning >}}

Note that `Override` action can be used only on `x86_64` architecture.

Similar to kprobe, the uprobe `Override` action allows to modify the return value
of user space call with `argError` argument, like:

```yaml
uprobes:
- path: "test"
  symbols:
  - "func"
  selectors:
  - matchActions:
    - action: Override
      argError: 123
```

Note that it can be successfully used only when following conditions are met:
- uprobe is attached to the beggining of the user space function;
- user space function is called via `call` instruction;
- user space function returns `int` type.

It's possible to override specific registers with arbitrary value with `argRegs`
argument, like:

```yaml
uprobes:
- path: "test"
  symbols:
  - "func"
  selectors:
  - matchActions:
    - action: Override
      argRegs:
      - "rax=11"
      - "rbp=(%rsp)"
      - "rip=8(%rsp)"
      - "rsp=8%rsp"
```

The `argRegs` argument is an array of strings where each string start with destination
register name followed by `=` and an assignment expression, which can be one of the
following types:

- constant `rax=11`
- register `rbp=%rsp`
- register plus offset `rip=8%rsp`
- dereference of register `rbp=(%rsp)`
- dereference of register plus offset `rsp=8(%rsp)`

{{< note >}}
This interface is likely to be changed in the future.
{{< /note >}}

### FollowFD action

{{< warning >}}
The FollowFD and related (UnfollowFD, CopyFD) actions have been deprecated due to being unsafe and
are planned to be removed in version 1.5.
{{< /warning >}}


The `FollowFD` action allows to create a mapping using a BPF map between file
descriptors and filenames. After its creation, the mapping can be maintained
through [`UnfollowFD`](#unfollowfd-action) and [`CopyFD`](#copyfd-action)
actions. Note that proper maintenance of the mapping is up to the tracing policy
writer.

`FollowFD` is typically used at hook points where a file descriptor and its
associated filename appear together. The kernel function `fd_install`
is a good example.

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

While the mapping between the file descriptor and filename remains in place
(that is, between `FollowFD` and `UnfollowFD` for the same file descriptor)
tracing policies may refer to filenames instead of file descriptors.  This
offers greater convenience and allows more functionality to reside inside the
kernel, thereby reducing overhead.

For instance, assume that you want to prevent writes into file
`/etc/passwd`. The system call `sys_write` only receives a file descriptor,
not a filename, as argument. Yet with a bracketing pair of `FollowFD`
and `UnfollowFD` actions in place the tracing policy that hooks into `sys_write`
can nevertheless refer to the filename `/etc/passwd`,
if it also marks the relevant argument as of type `fd`.

The following example combines actions `FollowFD` and `UnfollowFD` as well
as an argument of type `fd` to such effect:

```yaml
kprobes:
- call: "fd_install"
  syscall: false
  args:
  - index: 0
    type: int
  - index: 1
    type: "file"
  selectors:
  - matchArgs:
    - index: 1
      operator: "Equal"
      values:
      - "/tmp/passwd"
    matchActions:
    - action: FollowFD
      argFd: 0
      argName: 1
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
  - matchArgs:
    - index: 0
      operator: "Equal"
      values:
      - "/tmp/passwd"
    matchActions:
    - action: Sigkill
- call: "sys_close"
  syscall: true
  args:
  - index: 0
     type: "int"
  selectors:
  - matchActions:
    - action: UnfollowFD
      argFd: 0
      argName: 0
```

### UnfollowFD action

{{< warning >}}
The FollowFD and related (UnfollowFD, CopyFD) actions have been deprecated due to being unsafe and
are planned to be removed in version 1.5.
{{< /warning >}}

The `UnfollowFD` action takes a file descriptor from a system call and deletes
the corresponding entry from the BPF map, where it was put under the `FollowFD`
action.
It is typically used at hooks points where the scope of association between
a file descriptor and a filename ends. The system call `sys_close` is a
good example.

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

{{< warning >}}
The FollowFD and related (UnfollowFD, CopyFD) actions have been deprecated due to being unsafe and
are planned to be removed in version 1.5.
{{< /warning >}}

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

`Post` takes the `kernelStackTrace` parameter, when turned to `true` (by default to
`false`) it enables dump of the kernel stack trace to the hook point in kprobes
events. To dump user space stack trace set `userStackTrace` parameter to `true`.
For example, the following kprobe hook can be used to retrieve the
kernel stack to `kfree_skb_reason`, the function called in the kernel to drop
kernel socket buffers.

```yaml
kprobes:
  - call: kfree_skb_reason
    selectors:
    - matchActions:
      - action: Post
        kernelStackTrace: true
        userStackTrace: true
```

{{< caution >}}
By default Tetragon does not expose the linear addresses from kernel space or
user space, you need to enable the flag `--expose-stack-addresses` to get the
addresses along the rest.

Note that the Tetragon agent is using its privilege to read the kernel symbols
and their address. Being able to retrieve kernel symbols address can be used to
break kernel address space layout randomization (KASLR) so only privileged users
should be able to enable this feature and read events containing stack traces.
The same thing we can say about retrieving address for user mode processes.
Stack trace addresses can be used to bypass address space layout randomization (ASLR).
{{< /caution >}}

Once loaded, events created from this policy will contain a new `kernel_stack_trace`
field on the `process_kprobe` event with an output similar to:

```
{
  "address": "18446744072119856613",
  "offset": "5",
  "symbol": "kfree_skb_reason"
},
{
  "address": "18446744072119769755",
  "offset": "107",
  "symbol": "__sys_connect_file"
},
{
  "address": "18446744072119769989",
  "offset": "181",
  "symbol": "__sys_connect"
},
[...]
```

The "address" is the kernel function address, "offset" is the offset into the
native instruction for the function and "symbol" is the function symbol name.

User mode stack trace is contained in `user_stack_trace` field on the
`process_kprobe` event and looks like:

```
{
  "address": "140498967885099",
  "offset": "1209643",
  "symbol": "__connect",
  "module": "/usr/lib/x86_64-linux-gnu/libc.so.6"
},
{
  "address": "140498968021470",
  "offset": "1346014",
  "symbol": "inet_pton",
  "module": "/usr/lib/x86_64-linux-gnu/libc.so.6"
},
{
  "address": "140498971185511",
  "offset": "106855",
  "module": "/usr/lib/x86_64-linux-gnu/libcurl.so.4.7.0"
},
```
The "address" is the function address, "offset" is the function offset from the
beginning of the binary module. "module" is the absolute path of the binary file
to which address belongs. "symbol" is the function symbol name. "symbol" may be missing
if the binary file is stripped.

{{< note >}}
Information from `procfs (/proc/<pid>/maps)` is used to symbolize user
stack trace addresses. Stack trace addresses extraction and symbolizing are async.
It might happen that process is terminated and the `/proc/<pid>/maps` file will be
not existed at user stack trace symbolization step. In such case user stack traces
for very short living process might be not collected.

For Linux kernels before 5.15 user stack traces may be incomplete (some stack
traces entries may be missed).
{{< /note >}}

This output can be enhanced in a more human friendly using the `tetra getevents
-o compact` command. Indeed, by default, it will print the stack trace along
the compact output of the event similarly to this:

```
❓ syscall /usr/bin/curl kfree_skb_reason
Kernel:
   0xffffffffa13f2de5: kfree_skb_reason+0x5
   0xffffffffa13dda9b: __sys_connect_file+0x6b
   0xffffffffa13ddb85: __sys_connect+0xb5
   0xffffffffa13ddbd8: __x64_sys_connect+0x18
   0xffffffffa1714bd8: do_syscall_64+0x58
   0xffffffffa18000e6: entry_SYSCALL_64_after_hwframe+0x6e
User space:
   0x7f878cf2752b: __connect (/usr/lib/x86_64-linux-gnu/libc.so.6+0x12752b)
   0x7f878cf489de: inet_pton (/usr/lib/x86_64-linux-gnu/libc.so.6+0x1489de)
   0x7f878d1b6167:  (/usr/lib/x86_64-linux-gnu/libcurl.so.4.7.0+0x1a167)
```

The printing format for kernel stack trace is `"0x%x: %s+0x%x", address, symbol, offset`.
The printing format for user stack trace is `"0x%x: %s (%s+0x%x)", address, symbol, module, offset`.

{{< note >}}
Compact output will display missing addresses as `0x0`, see the above note on
`--expose-stack-addresses` for more info.
{{< /note >}}

#### File hash collection with IMA

`Post` takes the `imaHash` parameter, when turned to `true` (by default to
`false`) it adds file hashes in LSM events calculated by Linux integrity subsystem.
The following list of LSM hooks is supported:

- bprm_check_security
- bprm_committed_creds
- bprm_committing_creds
- bprm_creds_from_file
- file_ioctl
- file_lock
- file_open
- file_post_open
- file_receive
- mmap_file

First, you need to be sure that LSM BPF is [enabled](https://tetragon.io/docs/concepts/tracing-policy/hooks/#lsm-bpf).

To verify if IMA-measurement is available use the following command:

```shell
cat /boot/config-$(uname -r) | grep "CONFIG_IMA\|CONFIG_INTEGRITY"
```

The output should be similar to this if IMA-measurement is supported:

```
CONFIG_INTEGRITY=y
CONFIG_IMA=y
```

If provided above conditions are met, you can enable IMA-measurement by modifying `/etc/deault/grub`:

```
GRUB_CMDLINE_LINUX="lsm=integrity,bpf ima_policy=tcb"
```

Then, update the grub configuration and restart the system.

`ima_policy=` is used to define which files will be measured. `tcb` measures all executables run,
all mmap'd files for execution (such as shared libraries), all kernel modules loaded,
and all firmware loaded. Additionally, a files opened for read by root are measured as well.
`ima_policy=` can be specified multiple times, and the result is the union of the policies.
To know more about `ima_policy` you can follow this [link](https://ima-doc.readthedocs.io/en/latest/ima-policy.html).

{{< note >}}
Hash calculation with IMA subsystem and LSM BPF is supported from 5.11 kernel version.
For kernel versions below 6.1 is recommended to mount filesystems with `iversion`. Mounting with `iversion`
helps IMA not recalculating hash if file is not changed. From kernel 6.1 `iversion` is by default.
It is not necessary to enable IMA to calculate hashes with Tetragon if you have kernel 6.1+.
But hashes will be recalculated no matter if file is not changed. See implementation details of
`bpf_ima_file_hash` helper.
{{< /note >}}

The provided example of `TracingPolicy` collects hashes of executed binaries from
`zsh` and `bash` interpreters:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
      - index: 0
        type: "linux_binprm"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/zsh"
        - "/usr/bin/bash"
      matchActions:
        - action: Post
          imaHash: true
```

LSM event with file hash can look like this:

```json
{
  "process_lsm": {
    "process": {
        ...
    },
    "parent": {
        ...
    },
    "function_name": "bprm_check_security",
    "policy_name": "file-integrity-monitoring",
    "args": [
      {
        "linux_binprm_arg": {
          "path": "/usr/bin/grep",
          "permission": "-rwxr-xr-x"
        }
      }
    ],
    "action": "KPROBE_ACTION_POST",
    "ima_hash": "sha256:73abb4280520053564fd4917286909ba3b054598b32c9cdfaf1d733e0202cc96"
  },
}
```

`ima_hash` field contains information about hashing algorithm and the hash value itself
separated by ':'.

This output can be enhanced in a more human friendly using the
`tetra getevents -e PROCESS_LSM -o compact` command.

```
🔒 LSM     user-nix /usr/bin/zsh bprm_check_security
   /usr/bin/cat sha256:dd5526c5872cce104a80f4d4e7f787c56ab7686a5b8dedda0ba4e8b36a3c084c
🔒 LSM     user-nix /usr/bin/zsh bprm_check_security
   /usr/bin/grep sha256:73abb4280520053564fd4917286909ba3b054598b32c9cdfaf1d733e0202cc96
```

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
    index: 0
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

### Notify Enforcer action

The `NotifyEnforcer` action notifies the enforcer program to kill or override a syscall.

It's meant to be used on systems with kernel that lacks multi kprobe feature, that
allows to attach many kprobes quickly). To workaround that the enforcer sensor uses
the raw syscall tracepoint and attaches simple program to syscalls that we need to
kill or override.

The specs needs to have `enforcer` program definition, that instructs tetragon to load
the `enforcer` program and attach it to specified syscalls.

```yaml
spec:
  enforcers:
  - calls:
    - "list:dups"
```

The syscalls expects list of syscalls or `list:XXX` pointer to list.

Note that currently only single enforcer definition is allowed.


The `NotifyEnforcer` action takes 2 arguments.

```yaml
matchActions:
- action: "NotifyEnforcer"
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
  enforcers:
  - calls:
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
      - action: "NotifyEnforcer"
        argSig: 9
```

Note as mentioned above the `NotifyEnforcer` with enforcer program is meant to be used only on kernel versions
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

### USDT Set action

The `Set` action is specific for USDT probes and allows tetragon to write
value to configured USDT probe argument. This argument needs to meet few
conditions:

- It's stored in memory as `USDT deref` argument
- It has size of 4 bytes

Following command displays binary's ELF notes which includes all defined USDT probes.

```bash
$ readelf -n ./usdt-override
...
Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x0000003e       NT_STAPSDT (SystemTap probe descriptors)
    Provider: tetragon
    Name: test
    Location: 0x0000000000001135, Base: 0x0000000000002004, Semaphore: 0x0000000000000000
    Arguments: -4@-4(%rsp) -4@$1 -4@$2
```

- Please check `-4@-4(%rsp)` for first argument load, which is `USDT deref`.
- The `-4` in `-4@-4(%rsp)` stands for signed 4 bytes type.

Following C example is source for `usdt-override` from above. It defines USDT
probe with 3 arguments and first one meets the criteria for USDT return.

```c
int main(int argc, char **argv)
{
    volatile int ret = 0;
    int arg_1, arg_2;

    ...

    USDT(tetragon, test, ret, arg_1, arg_2);

    if (ret)
        return -1;

    ...

```

Note the `volatile` used for `ret` variable that ensures it will be used
via memory dereferencing in USDT probe.

We can then use following tetragon policy to trace this USDT probe and
force value `1` for output argument in case the `Set` action is executed.


```yaml
spec:
  usdts:
  - path: ".../usdt-override"
    provider: "tetragon"
    name: "test"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
    selectors:
      - matchActions:
        - action: Set
          argIndex: 0
          argValue: 1
```

The `Set` action uses following arguments:

- The `argIndex` defines position of the return argument.
- The `argValue` defined the actual value to write.

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
* InRange - In interval range
* NotInRange - Not in interval range

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

The operators relating to ports, addresses and protocol are used with sock, skb,
sockaddr and socket
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

The `InRange` and `NotInRange` operators accept integer values that are within the
specified range or NOT respectively. The range interval is specified with `:` separating
minimum and maximum value and includes both values as part of range.

For example following YAML snippet we match all values that are NOT `1,2,3,4 or 5`.

```yaml
matchArgs:
- index: 2
  operator: "NotInRange"
  values:
  - 1:5
```

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

Because BPF must be bounded we have to place limits on how many selectors can
exist.

- Max Selectors 5.
- Max PID values per selector 4
- Max MatchArgs per selector 5 (one per index)
- Max MatchArg Values per MatchArgs 4 (for operators like `Equal`, `NotEqual`,
  `GT`, `LT`, etc.)
- Max file match values (using `fd` or `file` arg): 8 on kernels ≥5.3, 2 on kernels <5.3
- String prefix max length: 256 chars
- String postfix max length: 128 chars

For an unlimited number of values, consider using the `InMap` or `NotInMap`
operators which store values in a BPF map.


## Return Actions filter

Return actions filters are a list of actions that execute when an return selector
matches. They are defined under `matchReturnActions` and currently support all
the [Actions filter](#actions-filter) `action` types.

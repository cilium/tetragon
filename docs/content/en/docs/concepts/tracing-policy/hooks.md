---
title: "Hook points"
weight: 2
description: "Hook points for Tracing Policies and arguments description"
---

Tetragon can hook into the kernel using `kprobes` and `tracepoints`, as well as in user-space
programs using `uprobes`. Users can configure these hook points using the correspodning sections of
the `TracingPolicy` specification (`.spec`). These hook points include arguments and return values
that can be specified using the `args` and `returnArg` fields as detailed in the following sections.

## Kprobes

Kprobes enables you to dynamically hook into any kernel function and execute BPF code. Because
kernel functions might change across versions, kprobes are highly tied to your kernel version and,
thus, might not be portable across different kernels.

Conveniently, you can list all kernel symbols reading the `/proc/kallsyms`
file. For example to search for the `write` syscall kernel function, you can
execute `sudo grep sys_write /proc/kallsyms`, the output should be similar to
this, minus the architecture specific prefixes.

```
ffffdeb14ea712e0 T __arm64_sys_writev
ffffdeb14ea73010 T ksys_write
ffffdeb14ea73140 T __arm64_sys_write
ffffdeb14eb5a460 t proc_sys_write
ffffdeb15092a700 d _eil_addr___arm64_sys_writev
ffffdeb15092a740 d _eil_addr___arm64_sys_write
```

You can see that the exact name of the symbol for the write syscall on our
kernel version is `__arm64_sys_write`. Note that on `x86_64`, the prefix would
be `__x64_` instead of `__arm64_`.

{{< caution >}}
Kernel symbols contain an architecture specific prefix when they refer to
syscall symbols. To write portable tracing policies, i.e. policies that can run
on multiple architectures, just use the symbol name without the prefix.

For example, instead of writing `call: "__arm64_sys_write"` or `call:
"__x64_sys_write"`, just write `call: "sys_write"`, Tetragon will adapt and add
the correct prefix based on the architecture of the underlying machine. Note
that the event generated as output currently includes the prefix.
{{< /caution >}}

In our example, we will explore a `kprobe` hooking into the
[`fd_install`](https://elixir.bootlin.com/linux/v6.1.9/source/fs/file.c#L602)
kernel function. The `fd_install` kernel function is called each time a file
descriptor is installed into the file descriptor table of a process, typically
referenced within system calls like `open` or `openat`. Hooking `fd_install`
has its benefits and limitations, which are out of the scope of this guide.

```yaml
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
```

{{< note >}}
Notice the `syscall` field, specific to a `kprobe` spec, with default value
`false`, that indicates whether Tetragon will hook a syscall or just a regular
kernel function. Tetragon needs this information because syscall and kernel
function use a [different ABI](https://gitlab.com/x86-psABIs/x86-64-ABI).
{{< /note >}}


Kprobes calls can be defined independently in different policies,
or together in the same Policy. For example, we can define trace multiple
kprobes under the same tracing policy:
```yaml
spec:
  kprobes:
  - call: "sys_read"
    syscall: true
    # [...]
  - call: "sys_write"
    syscall: true
    # [...]
```

## Tracepoints


Tracepoints are statically defined in the kernel and have the advantage of being stable across
kernel versions and thus more portable than kprobes.

To see the list of tracepoints available on your kernel, you can list them
using `sudo ls /sys/kernel/debug/tracing/events`, the output should be similar
to this.

```
alarmtimer    ext4            iommu           page_pool     sock
avc           fib             ipi             pagemap       spi
block         fib6            irq             percpu        swiotlb
bpf_test_run  filelock        jbd2            power         sync_trace
bpf_trace     filemap         kmem            printk        syscalls
bridge        fs_dax          kvm             pwm           task
btrfs         ftrace          libata          qdisc         tcp
cfg80211      gpio            lock            ras           tegra_apb_dma
cgroup        hda             mctp            raw_syscalls  thermal
clk           hda_controller  mdio            rcu           thermal_power_allocator
cma           hda_intel       migrate         regmap        thermal_pressure
compaction    header_event    mmap            regulator     thp
cpuhp         header_page     mmap_lock       rpm           timer
cros_ec       huge_memory     mmc             rpmh          tlb
dev           hwmon           module          rseq          tls
devfreq       i2c             mptcp           rtc           udp
devlink       i2c_slave       napi            sched         vmscan
dma_fence     initcall        neigh           scmi          wbt
drm           interconnect    net             scsi          workqueue
emulation     io_uring        netlink         signal        writeback
enable        iocost          oom             skb           xdp
error_report  iomap           page_isolation  smbus         xhci-hcd
```

You can then choose the subsystem that you want to trace, and look the
tracepoint you want to use and its format. For example, if we choose the
`netif_receive_skb` tracepoints from the `net` subsystem, we can read its
format with `sudo cat /sys/kernel/debug/tracing/events/net/netif_receive_skb/format`,
the output should be similar to the following.

```
name: netif_receive_skb
ID: 1398
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:void * skbaddr;   offset:8;       size:8; signed:0;
        field:unsigned int len; offset:16;      size:4; signed:0;
        field:__data_loc char[] name;   offset:20;      size:4; signed:0;

print fmt: "dev=%s skbaddr=%px len=%u", __get_str(name), REC->skbaddr, REC->len
```

Similarly to kprobes, tracepoints can also hook into system calls. For more
details, see the `raw_syscalls` and `syscalls` subysystems.

An example of tracepoints `TracingPolicy` could be the following, observing all
syscalls and getting the syscall ID from the argument at index 4:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "raw-syscalls"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "int64"
```
## Uprobes

Uprobes are similar to kprobes, but they allow you to dynamically hook into any
user-space function and execute BPF code. Uprobes are also tied to the binary
version of the user-space program, so they may not be portable across different
versions or architectures.

To use uprobes, you need to specify the path to the executable or library file,
and the symbol of the function you want to probe. You can use tools like
`objdump`, `nm`, or `readelf` to find the symbol of a function in a binary
file. For example, to find the readline symbol in `/bin/bash` using `nm`, you
can run:

```bash
nm -D /bin/bash | grep readline
```

The output should look similar to this, with a few lines redacted:
```
[...]
000000000009f2b0 T pcomp_set_readline_variables
0000000000097e40 T posix_readline_initialize
00000000000d5690 T readline
00000000000d52f0 T readline_internal_char
00000000000d42d0 T readline_internal_setup
[...]
```
You can see in the `nm` output: first the symbol value, then the symbol type,
for the `readline` symbol `T` meaning that this symbol is in the text (code)
section of the binary, and finally the symbol name. This confirms that the
`readline` symbol is present in the `/bin/bash` binary and might be a function
name that we can hook with a uprobe.

You can define multiple uprobes in the same policy, or in different policies.
You can also combine uprobes with kprobes and tracepoints to get a
comprehensive view of the system behavior.

Here is an example of a policy that defines an uprobe for the readline
function in the bash executable, and applies it to all processes that use the
bash binary:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "example-uprobe"
spec:
  uprobes:
  - path: "/bin/bash"
    symbol: "readline"
```

This example shows how to use uprobes to hook into the readline function
running in all the bash shells.

## Arguments

Kprobes, uprobes and tracepoints all share a needed arguments fields called `args`. It is a list of
arguments to include in the trace output. Tetragon's BPF code requires
information about the types of arguments to properly read, print and
filter on its arguments. This information needs to be provided by the user under the
`args` section. For the [available
types](https://github.com/cilium/tetragon/blob/main/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml#L64-L88),
check the [`TracingPolicy`
CRD](https://github.com/cilium/tetragon/blob/main/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml).

Following our example, here is the part that defines the arguments:
```yaml
args:
- index: 0
  type: "int"
- index: 1
  type: "file"
```

Each argument can optionally include a 'label' parameter, which will be included
in the output. This can be used to annotate the arguments to help with understanding
and processing the output. As an example, here is the same definition, with an
appropriate label on the int argument:
```yaml
args:
- index: 0
  type: "int"
  label: "FD"
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

Note that for some args types, `char_buf` and `char_iovec`, there are
additional fields named `returnCopy` and `sizeArgIndex` available:
- `returnCopy` indicates that the corresponding argument should be read later (when
  the kretprobe for the symbol is triggered) because it might not be populated
  when the kprobe is triggered at the entrance of the function. For example, a
  buffer supplied to `read(2)` won't have content until kretprobe is triggered.
- `sizeArgIndex` indicates the (1-based, see warning below) index of the arguments
  that represents the size of the `char_buf` or `iovec`. For example, for
  `write(2)`, the third argument, `size_t count` is the number of `char`
  element that we can read from the `const void *buf` pointer from the second
  argument. Similarly, if we would like to capture the `__x64_sys_writev(long,
  iovec *, vlen)` syscall, then `iovec` has a size of `vlen`, which is going to
  be the third argument.

{{< caution >}}
`sizeArgIndex` is inconsistent at the moment and does not take the index, but
the number of the index (or index + 1). So if the size is the third argument,
index 2, the value should be 3.
{{< /caution >}}

These flags can be combined, see the example below.

```yaml
- call: "sys_write"
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

Note that you can specify which arguments you would like to print from a
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

For `char_buf` type up to the 4096 bytes are stored. Data with bigger size are
cut and returned as truncated bytes.

You can specify `maxData` flag for `char_buf` type to read maximum possible data
(currently 327360 bytes), like:

```yaml
args:
- index: 1
  type: "char_buf"
  maxData: true
  sizeArgIndex: 3
- index: 2
  type: "size_t"
```

This field is only used for `char_buff` data. When this value is false (default),
the bpf program will fetch at most 4096 bytes.  In later kernels (>=5.4) tetragon
supports fetching up to 327360 bytes if this flag is turned on.

The `maxData` flag does not work with `returnCopy` flag at the moment, so it's
usable only for syscalls/functions that do not require return probe to read the
data.

## Return values

A `TracingPolicy` spec can specify that the return value should be reported in
the tracing output. To do this, the `return` parameter of the call needs to be
set to `true`, and the `returnArg` parameter needs to be set to specify the
`type` of the return argument. For example:

```yaml
- call: "sk_alloc"
  syscall: false
  return: true
  args:
  - index: 1
    type: int
    label: "family"
  returnArg:
    type: sock
```

In this case, the `sk_alloc` hook is specified to return a value of type `sock`
(a pointer to a `struct sock`). Whenever the `sk_alloc` hook is hit, not only
will it report the `family` parameter in index 1, it will also report the socket
that was created.

### Return values for socket tracking

A unique feature of a `sock` being returned from a hook such as `sk_alloc` is that
the socket it refers to can be tracked. Most networking hooks in the network stack
are run in a context that is not that of the process that owns the socket for which
the actions relate; this is because networking happens asynchronously and not
entirely in-line with the process. The `sk_alloc` hook does, however, occur in the
context of the process, such that the task, the PID, and the TGID are of the process
that requested that the socket was created.

Specifying socket tracking tells Tetragon to store a mapping between the socket
and the process' PID and TGID; and to use that mapping when it sees the socket in a
`sock` argument in another hook to replace the PID and TGID of the context with the
process that actually owns the socket. This can be done by adding a `returnArgAction`
to the call. Available actions are `TrackSock` and `UntrackSock`.
See [`TrackSock`](#tracksock-action) and [`UntrackSock`](#untracksock-action).

```yaml
- call: "sk_alloc"
  syscall: false
  return: true
  args:
  - index: 1
    type: int
    label: "family"
  returnArg:
    type: sock
  returnArgAction: TrackSock
```

Socket tracking is only available on kernels >=5.3.


## Lists

It's possible to define list of functions and use it in the kprobe's `call` field.

Following example traces all `sys_dup[23]` syscalls.


```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
  kprobes:
  - call: "list:dups"
```

It is basically a shortcut for following policy:

```yaml
spec:
  kprobes:
  - call: "sys_dup"
    syscall: true
  - call: "sys_dup2"
    syscall: true
  - call: "sys_dup3"
    syscall: true
```

As shown in subsequent examples, its main benefit is allowing a single definition for
calls that have the same filters.

The list is defined under `lists` field with arbitrary values for `name` and `values` fields.

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
    ...
```

It's possible to define multiple lists.

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
    name: "another"
    - "sys_open"
    - "sys_close"
```

Syscalls specified with `sys_` prefix are translated to their 64 bit equivalent function names.

It's possible to specify 32 bit syscall by using its full function name that
includes specific architecture native prefix (like `__ia32_` for `x86`):

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "__ia32_sys_dup"
    name: "another"
    - "sys_open"
    - "sys_close"
```

Specific list can be referenced in kprobe's `call` field with `"list:NAME"` value.

```yaml
spec:
  lists:
  - name: "dups"
  ...

  kprobes:
  - call: "list:dups"
```

The kprobe definition creates a kprobe for each item in the list and shares the rest
of the config specified for kprobe.

List can also specify `type` field that implies extra checks on the values (like for `syscall` type)
or denote that the list is generated automatically (see below).
User must specify `syscall` type for list with syscall functions. Also `syscall` functions
can't be mixed with regular functions in the list.

The additional selector configuration is shared with all functions in the list.
In following example we create 3 kprobes that share the same pid filter.


```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
  kprobes:
  - call: "list:dups"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - 12345
```

It's possible to use argument filter together with the `list`.

It's important to understand that the argument will be retrieved by using the specified
argument type for all the functions in the list.

Following example adds argument filter for first argument on all functions in dups list to
match value 9999.

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
  kprobes:
  - call: "list:dups"
    args:
    - index: 0
      type: int
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - 9999
```

There are two additional special types of generated lists.

The `generated_syscalls` type of list that generates list with all possible
syscalls on the system.

Following example traces all syscalls for `/usr/bin/kill` binary.

```yaml
spec:
  lists:
  - name: "all-syscalls"
    type: "generated_syscalls"
  kprobes:
  - call: "list:all-syscalls"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/kill"
```

The `generated_ftrace` type of list that generates functions from ftrace `available_filter_functions`
file with specified filter. The filter is specified with `pattern` field and expects regular expression.

Following example traces all kernel `ksys_*` functions for `/usr/bin/kill` binary.

```yaml
spec:
  lists:
  - name: "ksys"
    type: "generated_ftrace"
    pattern: "^ksys_*"
  kprobes:
  - call: "list:ksys"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/kill"
```

Note that if syscall list is used in selector with InMap operator, the argument type needs to be `syscall64`, like.

```yaml
spec:
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "__ia32_sys_dup"
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
```

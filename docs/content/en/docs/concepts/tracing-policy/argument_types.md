---
title: "Argument types"
weight: 2
description: "Argument types for data retrieval"
---

Selectors are a way to perform in-kernel BPF filtering on the events to
export, or on the events on which to apply an action.

A `TracingPolicy` can contain from 0 to 5 selectors. A selector is composed of
1 or more filters. The available filters are the following:
- [`file`](#file): path from file object
- [`dentry`](#dentry): path from dentry object


## `file`

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


## dentry


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

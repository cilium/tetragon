---
title: "FAQ"
weight: 99
description: "List of frequently asked questions"
aliases: ["/docs/faq"]
---

### What is the minimum Linux kernel version to run Tetragon?

Tetragon needs Linux kernel version 4.19 or greater.

We currently run tests on stable long-term support kernels 4.19, 5.4, 5.10,
5.15 and bpf-next, see [this test workflow](https://github.com/cilium/tetragon/actions/workflows/vmtests.yml)
for up to date information. Not all Tetragon features work with older kernel
versions. BPF evolves rapidly and we recommend you use the most recent stable
kernel possible to get the most out of Tetragon's features.

Note that Tetragon needs [BTF support]({{< ref "/docs/installation/faq#tetragon-failed-to-start-complaining-about-a-missing-btf-file">}})
which might take some work on older kernels.

### What are the Linux kernel configuration options needed to run Tetragon?

This is the list of needed configuration options, note that this might evolve
quickly with new Tetragon features:

```
# CORE BPF
CONFIG_BPF
CONFIG_BPF_JIT
CONFIG_BPF_JIT_DEFAULT_ON
CONFIG_BPF_EVENTS
CONFIG_BPF_SYSCALL
CONFIG_HAVE_BPF_JIT
CONFIG_HAVE_EBPF_JIT
CONFIG_FTRACE_SYSCALLS

# BTF
CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF_MODULES

# Enforcement
CONFIG_BPF_KPROBE_OVERRIDE

# CGROUP and Process tracking
CONFIG_CGROUPS=y        Control Group support
CONFIG_MEMCG=y          Memory Control group
CONFIG_BLK_CGROUP=y     Generic block IO controller
CONFIG_CGROUP_SCHED=y
CONFIG_CGROUP_PIDS=y    Process Control group
CONFIG_CGROUP_FREEZER=y Freeze and unfreeze tasks controller
CONFIG_CPUSETS=y        Manage CPUSETs
CONFIG_PROC_PID_CPUSET=y
CONFIG_CGROUP_DEVICE=Y  Devices Control group
CONFIG_CGROUP_CPUACCT=y CPU accouting controller
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y     Attach eBPF programs to a cgroup
CGROUP_FAVOR_DYNMODS=y  (optional)  >= 6.0
  Reduces the latencies of dynamic cgroup modifications at the
  cost of making hot path operations such as forks and exits
  more expensive.
  Platforms with frequent cgroup migrations could enable this
  option as a potential alleviation for pod and containers
  association issues.
```

If the system is still on the old Cgroupv1 interface and the running kernel version
is >= 6.11 then these kernel config options are required:
```
# CGROUPv1 Process tracking on kernels >= 6.11
CONFIG_MEMCG_V1=y
CONFIG_CPUSETS_V1=y
```

At runtime, to probe if your kernel has sufficient features turned on, you can
run `tetra` with root privileges with the `probe` command:

```shell
sudo tetra probe
```

You can also run this command directly from the tetragon container image on a
Kubernetes cluster node. For example:

```shell
kubectl run bpf-probe --image=quay.io/cilium/tetragon-ci:latest --privileged --restart=Never -it --rm --command -- tetra probe
```

The output should be similar to this (with boolean values depending on your
actual configuration):

```
override_return: true
buildid: true
kprobe_multi: false
fmodret: true
fmodret_syscall: true
signal: true
large: true
```

### Tetragon failed to start complaining about a missing BTF file

You might have encountered the following issues:
```
level=info msg="BTF discovery: default kernel btf file does not exist" btf-file=/sys/kernel/btf/vmlinux
level=info msg="BTF discovery: candidate btf file does not exist" btf-file=/var/lib/tetragon/metadata/vmlinux-5.15.49-linuxkit
level=info msg="BTF discovery: candidate btf file does not exist" btf-file=/var/lib/tetragon/btf
[...]
level=fatal msg="Failed to start tetragon" error="tetragon, aborting kernel autodiscovery failed: Kernel version \"5.15.49-linuxkit\" BTF search failed kernel is not included in supported list. Please check Tetragon requirements documentation, then use --btf option to specify BTF path and/or '--kernel' to specify kernel version"
```

Tetragon needs BTF ([BPF Type Format](https://www.kernel.org/doc/html/latest/bpf/btf.html))
support to load its BPF programs using CO-RE ([Compile Once - Run Everywhere](https://nakryiko.com/posts/bpf-core-reference-guide/)).
In brief, CO-RE is useful to load BPF programs that have been compiled on a
different kernel version than the target kernel. Indeed, kernel structures
change between versions and BPF programs need to access fields in them. So
CO-RE uses the [BTF file of the kernel](https://nakryiko.com/posts/btf-dedup/)
in which you are loading the BPF program to know the differences between the
struct and patch the fields offset in the accessed structures. CO-RE allows
portability of the BPF programs but requires a kernel with BTF enabled.

Most of the [common Linux distributions](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
now ship with BTF enabled and do not require any extra work, this is kernel
option `CONFIG_DEBUG_INFO_BTF=y`. To check if BTF is enabled on your Linux
system and see the BTF data file of your kernel, the standard location is
`/sys/kernel/btf/vmlinux`. By default, Tetragon will look for this file (this
is the first line in the log output above).

If your kernel does not support BTF you can:
- Retrieve the BTF file for your kernel version from an external source.
- Build the BTF file from your kernel debug symbols. You will need pahole to
  add BTF metadata to the debugging symbols and LLVM minimize the medata size.
- Rebuild your kernel with `CONFIG_DEBUG_INFO_BTF` to `y`.

Tetragon will also look into `/var/lib/tetragon/btf` for the `vmlinux` file
(this is the third line in the log output above). Or you can use the `--btf`
flag to directly indicate Tetragon where to locate the file.

If you encounter this issue while using Docker Desktop on macOS, please refer
to [can I run Tetragon on Mac computers](#can-i-run-tetragon-on-mac-computers).

### Can I install and use Tetragon in standalone mode (outside of k8s)?

Yes! Refer to the [Container]({{< ref "/docs/installation/container">}}) or
[Package]({{< ref "/docs/installation/package">}}) installation guides.

Otherwise you can build Tetragon from source by running `make` to generate standalone
binaries.
Make sure to take a look at the [Development Setup](/docs/contribution-guide/development-setup/)
guide for the build requirements. Then use `sudo ./tetragon --bpf-lib bpf/objs`
to run Tetragon.

### Can I run Tetragon on Mac computers?

Yes! You can run Tetragon locally by running a Linux virtual machine on your
Mac.

On macOS running on amd64 (also known as Intel Mac) and arm64 (also know as
Apple Silicon Mac), open source and commercial solutions exists to run virtual
machines, here is a list of popular open source projects that you can use:
- [Lima: Linux virtual machines](https://github.com/lima-vm/lima): website
  [lima-vm.io](https://lima-vm.io/).
- [UTM: Virtual machines for iOS and macOS](https://github.com/utmapp/UTM):
  website [mac.getutm.app](https://mac.getutm.app/).
- [VirtualBox](https://www.virtualbox.org/browser): website
  [virtualbox.org](https://www.virtualbox.org/) _(arm64 in developer preview)_.

You can use these solutions to run a [recent Linux distribution](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
that ships with BTF debug information support.

Please note that you need to use a recent Docker Desktop version on macOS (for example `24.0.6`
with Kernel `6.4.16-linuxkit`), because the Linux
virtual machine provided by older Docker Desktop versions lacked support for the BTF debug information.
The BTF debug information file is needed for [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
in order to load sensors of Tetragon. Run the following commands to see if Tetragon can be used on your Docker Desktop version:

```shell
# The Kernel needs to be compiled with CONFIG_DEBUG_INFO_BTF and
# CONFIG_DEBUG_INFO_BTF_MODULES support:
$ docker run -it --rm --privileged --pid=host ubuntu \
    nsenter -t 1 -m -u -n -i sh -c \
    'cat /proc/config.gz | gunzip | grep CONFIG_DEBUG_INFO_BTF'
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y

# "/sys/kernel/btf/vmlinux" should be present:
$ docker run -it --rm --privileged --pid=host ubuntu \
    nsenter -t 1 -m -u -n -i sh -c 'ls -la /sys/kernel/btf/vmlinux'
-r--r--r--    1 root     root       4988627 Nov 21 20:33 /sys/kernel/btf/vmlinux
```

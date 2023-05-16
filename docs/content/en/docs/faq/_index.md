---
title: "FAQ"
weight: 7
description: "List of frequently asked questions"
---

#### Can I install and use Tetragon in standalone mode (outside of k8s)?

Yes! You can run `make` to generate standalone binaries and run them directly.
Make sure to take a look at the [Development Setup](/docs/contribution-guide/development-setup/)
guide for the build requirements. Then use `sudo ./tetragon --bpf-lib bpf/objs`
to run Tetragon.

#### CI is complaining about Go module vendoring, what do I do?

You can run `make vendor` then add and commit your changes.

#### CI is complaining about a missing "signed-off-by" line. What do I do?

You need to add a signed-off-by line to your commit messages. The easiest way
to do this is with `git fetch origin/main && git rebase --signoff origin/main`.
Then push your changes.

#### Can I run Tetragon on Mac computers?

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

Please note that you cannot use Docker Desktop on macOS, because the Linux
virtual machine provided by Docker lacks support for the BTF debug information.
The BTF debug information file is needed for [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
in order to load sensors of Tetragon. While it is technically possible to
manually generate the BTF metadata, you will need the kernel debug symbols, and
[Docker stopped pushing](https://hub.docker.com/r/linuxkit/kernel) the kernel
images containing those debug symbols.

Issues are open on the GitHub repository for [Docker Desktop on macOS](https://github.com/docker/for-mac/issues/6800)
and [linuxkit](https://github.com/linuxkit/linuxkit/issues/3755), the project
used to build the kernel used by Docker Desktop. If you would like Docker
Desktop to support BTF, feel free to support those issues.

#### Go compiler is complaining about missing symbols in `pkg/bpf`

You might end up with the output of the Go compiler looking similar to this:
```
# github.com/cilium/tetragon/pkg/bpf
pkg/bpf/map_linux.go:174:9: undefined: bpfAttrObjOp
pkg/bpf/map_linux.go:266:19: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:310:19: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:318:16: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:415:9: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:422:9: undefined: UpdateElementFromPointers
pkg/bpf/map_linux.go:455:9: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:466:9: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:496:9: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:515:9: undefined: bpfAttrMapOpElem
pkg/bpf/map_linux.go:515:9: too many errors
```

It is likely because this package uses [CGO](https://pkg.go.dev/cmd/cgo) and
you might be missing a C compiler or the Go toolchain might fail detecting one.
Also note from the [CGO documentation](https://pkg.go.dev/cmd/cgo) that CGO is
disabled by default when cross-compiling:
> The cgo tool is enabled by default for native builds on systems where it is
> expected to work. It is disabled by default when cross-compiling as well as
> when the CC environment variable is unset and the default C compiler
> (typically gcc or clang) cannot be found on the system PATH. You can override
> the default by setting the CGO_ENABLED environment variable when running the
> go tool: set it to 1 to enable the use of cgo, and to 0 to disable it. [...]

If you encounter the issue under Linux:
- Check your Go environment information with `go env CC`. The output should be
  similar to `gcc`. Verify that `gcc` is installed with `gcc --version`. If
  it's not the case, install `gcc`.
- If you prefer to use clang, you can manually set the `CC` env variable to
  `clang`, for example building tetragon with `CC=clang make tetragon`. To
  persistently change the value of the CC go environment variable you can use
  `go env -w "CC=clang"`.

#### Tetragon failed to start complaining about a missing BTF file

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


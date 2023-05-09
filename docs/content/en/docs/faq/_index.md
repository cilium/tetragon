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



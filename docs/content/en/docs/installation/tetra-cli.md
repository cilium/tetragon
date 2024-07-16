---
title: "Install tetra CLI"
weight: 4
description: "To interact with Tetragon, install the Tetragon client CLI tetra"
---

This guide presents various methods to install `tetra` in your environment.

## Install the latest release

### Autodetect your environment

This shell script autodetects the OS and the architecture, downloads the
archive of the binary and its SHA 256 digest, compares that the actual digest
with the supposed one, installs the binary, and removes the download artifacts.

{{< note >}}
This installation method requires a working Go toolchain, `curl(1)`, and the
`sha256sum(1)` utilities. For Go, see how to [install the latest Go release](https://go.dev/doc/install)
and for the curl and checksum utility, it is usually distributed in common
Linux distribution but you can usually find them respectively under the package
`curl` and `coreutils`.
{{< /note >}}

```shell
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L --remote-name-all https://github.com/cilium/tetragon/releases/latest/download/tetra-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
sha256sum --check tetra-${GOOS}-${GOARCH}.tar.gz.sha256sum
sudo tar -C /usr/local/bin -xzvf tetra-${GOOS}-${GOARCH}.tar.gz
rm tetra-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
```

### Quick install for each environment

This installation method retrieves the adapted archived for your environment,
extract it and install it in the `/usr/local/bin` directory.

{{< note >}}
This installation method requires only `curl(1)` that should be already
installed in your environment, otherwise you can usually find it under the
`curl` package.
{{< /note >}}

{{< note >}}
The architecture amd64 is also referred to as x86_64 or Intel, and arm64 is also
referred to as aarch64 or Apple Silicon for Mac computers.
{{< /note >}}

{{< tabpane lang="shell" >}}

{{< tab header="Linux amd64" >}}
curl -L https://github.com/cilium/tetragon/releases/latest/download/tetra-linux-amd64.tar.gz | tar -xz
sudo mv tetra /usr/local/bin
{{< /tab >}}

{{< tab header="Linux arm64" >}}
curl -L https://github.com/cilium/tetragon/releases/latest/download/tetra-linux-arm64.tar.gz | tar -xz
sudo mv tetra /usr/local/bin
{{< /tab >}}

{{< tab header="macOS amd64" >}}
curl -L https://github.com/cilium/tetragon/releases/latest/download/tetra-darwin-amd64.tar.gz | tar -xz
sudo mv tetra /usr/local/bin
{{< /tab >}}

{{< tab header="macOS arm64" >}}
curl -L https://github.com/cilium/tetragon/releases/latest/download/tetra-darwin-arm64.tar.gz | tar -xz
sudo mv tetra /usr/local/bin
{{< /tab >}}

{{< tab header="Windows amd64" >}}
curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetra-windows-amd64.tar.gz
tar -xzf tetra-windows-amd64.tar.gz
# move the binary in a directory in your PATH
{{< /tab >}}

{{< tab header="Windows arm64" >}}
curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetra-windows-arm64.tar.gz
tar -xzf tetra-windows-arm64.tar.gz
# move the binary in a directory in your PATH
{{< /tab >}}
{{< /tabpane >}}

### Install using homebrew

[Homebrew](https://brew.sh/) is a package manager for macOS and Linux.
[A formulae is available](https://formulae.brew.sh/formula/tetra#default) to
fetch precompiled binaries. You can also use it to build from sources (using the
`--build-from-source` flag) with a Go dependency.

```shell
brew install tetra
```

## Install a specific release

You can retrieve the release of `tetra` along the release of Tetragon on GitHub
at the following URL: https://github.com/cilium/tetragon/releases.

To download a specific release you can use the following script, replacing the
`OS`, `ARCH` and `TAG` values with your desired options.

```shell
OS=linux
ARCH=amd64
TAG=v0.9.0
curl -LO https://github.com/cilium/tetragon/releases/download/${TAG}/tetra-${OS}-${ARCH}.tar.gz | tar -xz
```

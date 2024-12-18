---
title: "Development setup"
weight: 1
description: "This will help you getting started with your development setup to build Tetragon"
---

## Building and running Tetragon

For local development, you will likely want to build and run bare-metal Tetragon.

### Requirements

- A Go toolchain with the [version specified in the main `go.mod`](https://github.com/cilium/tetragon/blob/main/go.mod#L4);
- GNU make;
- A running Docker service (you can use Podman as well);
- The [docker-buildx-plugin](https://github.com/docker/buildx?tab=readme-ov-file#linux-packages) (you may already have this);
- For building tests, `libcap` and `libelf` (in Debian systems, e.g., install
  `libelf-dev` and `libcap-dev`).

### Build everything

You can build most Tetragon targets as follows (this can take time as it builds
all the targets needed for testing, see [minimal build](#minimal-build)):

```shell
make
```

If you want to use `podman` instead of `docker`, you can do the following (assuming you
need to use `sudo` with `podman`):

```shell
CONTAINER_ENGINE='sudo podman' make
```
You can ignore `/bin/sh: docker: command not found` in the output.

To build using the local clang, you can use:
```shell
CONTAINER_ENGINE='sudo podman' LOCAL_CLANG=1 LOCAL_CLANG_FORMAT=1 make
```

See [Dockerfile.clang](https://github.com/cilium/tetragon/blob/main/Dockerfile.clang)
for the minimal required version of `clang`.

### Minimal build

To build the `tetragon` binary, the BPF programs and the `tetra` CLI binary you
can use:
```shell
make tetragon tetragon-bpf tetra
```

### Run Tetragon

You should now have a `./tetragon` binary, which can be run as follows:

```shell
sudo ./tetragon --bpf-lib bpf/objs
```

Notes:

1. The `--bpf-lib` flag tells Tetragon where to look for its compiled BPF
   programs (which were built in the `make` step above).

2. If Tetragon fails with an error `"BTF discovery: candidate btf file does not
   exist"`, then make sure that your kernel support [BTF](#btf-requirement),
   otherwise place a BTF file where Tetragon can read it and specify its path
   with the `--btf` flag. See more about that
   [in the FAQ]({{< ref "/docs/installation/faq#tetragon-failed-to-start-complaining-about-a-missing-btf-file" >}}).

## Building and running a Docker image

The base kernel should support [BTF](https://github.com/cilium/tetragon#btf-requirement)
or a BTF file should be bind mounted on top of `/var/lib/tetragon/btf` inside
container.

To build Tetragon image:
```shell
make image
```

To run the image:
```shell
docker run --name tetragon \
   --rm -it -d --pid=host \
   --cgroupns=host --privileged \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   cilium/tetragon:latest
```

Run the `tetra` binary to get Tetragon events:
```shell
docker exec -it tetragon \
   bash -c "/usr/bin/tetra getevents -o compact"
```

## Building and running as a systemd service

To build Tetragon tarball:
```shell
make tarball
```

## Running Tetragon in kind

This command will setup tetragon, kind cluster and install tetragon in it. Ensure docker, kind, kubectl, and helm are installed.

```shell
# Setup tetragon on kind
make kind-setup
```

Verify that Tetragon is installed by running:
```shell
kubectl get pods -n tetragon
```

## Local Development in Vagrant Box

If you are on an intel Mac, use Vagrant to create a dev VM:

```shell
vagrant up
vagrant ssh
make
```

If you are getting an error, you can try to run `sudo launchctl load
/Library/LaunchDaemons/org.virtualbox.startup.plist` (from [a Stackoverflow
answer](https://stackoverflow.com/questions/18149546/macos-vagrant-up-failed-dev-vboxnetctl-no-such-file-or-directory)).

## Local Development with Apple Silicon Mac

Use [Lima](https://lima-vm.io/) to create a Linux VM if you are using a Mac with
Apple silicon. For example:

{{< warning >}}
The following commands create a VM, and make the mount for your home directory
on the host writable. Tweak `~/.lima/tetragon/lima.yaml` if you prefer to only
mount Tetragon directory as writable.
{{< /warning >}}

{{< note >}}
The following commands install Golang 1.23. You may want to install a newer
version if it's available in https://launchpad.net/~longsleep/+archive/ubuntu/golang-backports.
{{< /note >}}

First create a VM using [Lima](https://lima-vm.io/):

```shell
brew install lima
limactl create --mount-writable --tty=false --name=tetragon
limactl start tetragon
limactl shell tetragon
```

Then install needed dependencies inside the VM:

```shell
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt update
sudo apt install -y golang-1.23 libelf-dev libcap-dev make
export CONTAINER_ENGINE=nerdctl
export PATH=$PATH:/usr/lib/go-1.23/bin
```

You can now build Tetragon in your VM:

```shell
make -j3 tetragon-bpf tetragon tetra
```

## What's next

- See how to [make your first changes](/docs/contribution-guide/making-changes).


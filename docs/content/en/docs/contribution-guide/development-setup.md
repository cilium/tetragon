---
title: "Development setup"
weight: 1
description: "This will help you getting started with your development setup to build Tetragon"
---

### Building and Running Tetragon

For local development, you will likely want to build and run bare-metal Tetragon.

Requirements:
- go 1.18
- GNU make
- A running docker service
- `libcap` and `libelf` (in Debian systems, e.g., install `libelf-dev` and
  `libcap-dev`)

You can build Tetragon as follows:

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

See
[Dockerfile.clang](https://github.com/cilium/tetragon/blob/main/Dockerfile.clang)
for the minimal required version of `clang`.

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
   with the `--btf` flag.

### Running Code Generation

Tetragon uses code generation based on protoc to generate large amounts of
boilerplate code based on our protobuf API. We similarly use automatic
generation to maintain our k8s CRDs. Whenever you make changes to these files,
you will be required to re-run code generation before your PR can be accepted.

To run codegen from protoc, run the following command from the root of the
repository:
```shell
make codegen
```

And to run k8s CRD generation, run the following command from the root of the repository:
```shell
make generate
```

Finally, should you wish to modify any of the resulting codegen files (ending
in` .pb.go`), do not modify them directly. Instead, you can edit the files in
`cmd/protoc-gen-go-tetragon` and then re-run `make codegen`.

### Building and running a Docker image

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
   cilium/tetragon:latest \
   bash -c "/usr/bin/tetragon"
```

Run the `tetra` binary to get Tetragon events:
```shell
docker exec -it tetragon \
   bash -c "/usr/bin/tetra getevents -o compact"
```

### Building and running as a systemd service

To build Tetragon tarball:
```shell
make tarball
```

The produced tarball will be inside directory `./build/`, then follow the
[Package deployment guide](/docs/getting-started/deployment/package/) to
install it as a systemd service.

### Running Tetragon in kind

The scripts in contrib/localdev will help you run Tetragon locally in a kind
cluster. First, ensure that docker, kind, kubectl, and helm are installed on
your system. Then, run the following commands:

```shell
# Build Tetragon agent and operator images
make LOCAL_CLANG=0 image image-operator

# Bootstrap the cluster
contrib/localdev/bootstrap-kind-cluster.sh

# Install Tetragon
contrib/localdev/install-tetragon.sh --image cilium/tetragon:latest --operator cilium/tetragon-operator:latest
```

Verify that Tetragon is installed by running:
```shell
kubectl get pods -n kube-system
```

### Local Development in Vagrant Box

If you are on a Mac, use Vagrant to create a dev VM:

```shell
vagrant up
vagrant ssh
make
```

If you are getting an error, you can try to run `sudo launchctl load
/Library/LaunchDaemons/org.virtualbox.startup.plist` (from [a Stackoverflow
answer](https://stackoverflow.com/questions/18149546/macos-vagrant-up-failed-dev-vboxnetctl-no-such-file-or-directory)).

### Local Development in Minikube

You can also run the tetragon agent directly (instead of in a pod). Here we
describe how this can be done in minikube:

```shell
minikube start --driver=kvm2
minikube mount $HOME:$HOME # so that we can use .kube/config
./tetragon-operator --kube-config ~/.kube/config
make STATIC=1 tetragon
minikube ssh --  'sudo mkdir -p /var/run/cilium/tetragon'
minikube ssh sudo "sh -c 'NODE_NAME=minikube /home/kkourt/src/tetragon/tetragon --bpf-lib /home/kkourt/src/tetragon/bpf/objs --server-address unix:///var/run/cilium/tetragon/tetragon.sock --enable-k8s-api --k8s-kubeconfig-path /home/kkourt/.kube/config'"
```

### What's next

See how to [make your first changes](/docs/contribution-guide/making-changes).


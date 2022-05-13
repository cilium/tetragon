Building and Running Tetragon
==============================

For local development, you will likely want to build and run bare-metal Tetragon.

Tetragon relies on a permanent fork of libbpf and a fork of clang with some custom patches in order
to build and load its BPF programs correctly. We first need to get a local copy of both, which can be done
with:

```
make tools-install
```

After running the above command, you are ready to build Tetragon as follows:

```
LD_LIBRARY_PATH=$(realpath ./lib) make LOCAL_CLANG=0
```

You should now have a `./tetragon` binary, which can be run as follows:

```
sudo LD_LIBRARY_PATH=$(realpath ./lib) ./tetragon --bpf-lib bpf/objs
```

Note that we need to specify the `LD_LIBRARY_PATH` as shown above so that Tetragon can find
the correct libbpf to use at runtime. The `--bpf-lib` flag tells Tetragon where to look
for its compiled BPF programs (which were built in the `make` step above).

Running Code Generation
=======================

Tetragon uses code generation based on protoc to generate large amounts of boilerplate
code based on our protobuf API. We similarly use automatic generation to maintain our k8s
CRDs. Whenever you make changes to these files, you will be required to re-run code generation
before your PR can be accepted.

To run codegen from protoc, run the following command from the root of the repository:
```
make codegen
```

And to run k8s CRD generation, run the following command from the root of the repository:
```
make generate
```

Finally, should you wish to modify any of the resulting codegen files (ending in .pb.go),
do not modify them directly. Instead, you can edit the files in
`cmd/protoc-gen-go-tetragon` and then re-run `make codegen`.

Running Tetragon in kind
========================

The scripts in contrib/localdev will help you run Tetragon locally in a kind cluster.
First, ensure that docker, kind, kubectl, and helm are installed on your system.
Then, run the following commands:

```
# Build Tetragon agent and operator images
LD_LIBRARY_PATH=$(realpath ./lib) make LOCAL_CLANG=0 image image-operator

# Bootstrap the cluster
contrib/localdev/bootstrap-kind-cluster.sh

# Install Tetragon
contrib/localdev/install-tetragon.sh --image cilium/tetragon:latest --operator cilium/tetragon-operator:latest
```

Verify that Tetragon is installed by running:
```
kubectl get pods -n kube-system
```

Using Dev VM
============

If you are on a Mac, use Vagrant to create a dev VM:

    vagrant up
    vagrant ssh
    make

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
sudo LD_LIBRARY_PATH=$(realpath ./lib) ./tetragon --hubble-lib bpf/objs
```

Note that we need to specify the `LD_LIBRARY_PATH` as shown above so that Tetragon can find
the correct libbpf to use at runtime. The `--hubble-lib` flag tells Tetragon where to look
for its compiled BPF programs (which were built in the `make` step above).

Using Dev VM
============

If you are on a Mac, use Vagrant to create a dev VM:

    vagrant up
    vagrant ssh
    make

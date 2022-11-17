## Testing

This directory is used for multi-kernel testing using litte-vm-helper
(https://github.com/cilium/little-vm-helper/).

### Usage

NOTE: For now, commands need to be executed from the top-level tetragon directory.


Build everything:

```
$ make -C tests/vmtests
make: Entering directory '/home/kkourt/src/tetragon/tests/vmtests'
go build ../cmd/tetragon-tester
go build ../cmd/tetragon-vmtests-run
make: Leaving directory '/home/kkourt/src/tetragon/tests/vmtests'
```


Download rootfs images and kernels in `tests/vmtests/test-data`
```
$ ./tests/vmtests/fetch-data.sh 4.19 5.4 bpf-next
...
$ ls tests/vmtests/test-data/images tests/vmtests/test-data/kernels
tests/vmtests/test-data/images:
base.qcow2

tests/vmtests/test-data/kernels:
4.19/ 5.4/  bpf-next/
```

Run tests on 5.4:
```
$ make test-compile # <- this will build the test binaries
$ ./tests/vmtests/tetragon-vmtests-run \
	--kernel tests/vmtests/test-data/kernels/5.4/boot/vmlinuz-5.4.206 \
	--base tests/vmtests/test-data/images/base.qcow2
```

Run tests on 5.4, without KVM acceleration. Doing so, makes the run closer to the GH action
environment (which do not support nested virtualization) and it  also uncover other issues due to
the unconventional timing.

```
$ ./tests/vmtests/tetragon-vmtests-run \
	--kernel tests/vmtests/test-data/kernels/5.4/boot/vmlinuz-5.4.206 \
	--base tests/vmtests/test-data/images/base.qcow2 \
	--qemu-disable-kvm
```

Run a single test 20 times on 4.19 and fail fast

```
$ seq 20 | xargs -I {} echo pkg.sensors.tracing:TestGenericTracepointRawSyscall > tests/vmtests/repeat-raw-syscall
$ ./tests/vmtests/tetragon-vmtests-run \
	--kernel tests/vmtests/test-data/kernels/4.19/boot/vmlinuz-4.19.262 \
	--btf-file tests/vmtests/test-data/kernels/4.19/boot/btf-4.19.262 \
	--base tests/vmtests/test-data/images/base.qcow2  \
	--testsfile tests/vmtests/repeat-raw-syscall \
	--fail-fast
```

Just Boot the VM. User

```
$ ./tests/vmtests/tetragon-vmtests-run \
	--kernel tests/vmtests/test-data/kernels/5.4/boot/vmlinuz-5.4.206 \
	--base tests/vmtests/test-data/images/base.qcow2 \
	--qemu-disable-kvm
```

### Design notes

There are two go programs: one that runs inside the VM (tetragon-tester), and one that runs outside
the VM (tetragon-vmtests-run). tetragon-vmtests-run, running outside, will prepare an image and then
boot it using qemu. The image will be build based on the base image provided with --base.
Some of the steps of preparing the image are:
 * add tetragon-tester as a systemd service, so that it starts when the machine boots
 * mount the tetragon source directory inside the VM (currently, as a 9p filesystem)
 * write a configuration file to be read by tetragon-tester

Once the machine boots, the systemd will start the service that will execute the tests. When the
tests complete, the machine will be powered off.

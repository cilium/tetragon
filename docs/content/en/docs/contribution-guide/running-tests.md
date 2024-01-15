---
title: "Running tests"
weight: 3
description: "Learn how to run the tests of the project"
---

Tetragon has several types of tests:
- Go tests, composed of unit tests for userspace Go code and Go and BPF code.
- BPF unit tests, testing specifing BPF functions.
- E2E tests, for end-to-end tests, installing Tetragon in Kubernetes clusters
  and checking for specific features.

Those tests are running in the Tetragon CI on various kernels[^1] and various
architectures (amd64 and arm64).

[^1]: For the detailed list, search for `jobs.test.strategy.matrix.kernel` in
[github.com/cilium/tetragon/.github/workflows/vmtests.yml](https://github.com/cilium/tetragon/blob/main/.github/workflows/vmtests.yml)

## Go tests

To run the Go tests locally, you can use:

```shell
make test
```

Use `EXTRA_TESTFLAGS` to add flags to the `go test` command.

### Test specific kernels

To run the Go tests on various kernel versions, we use vmtests with
[cilium/little-vm-helper](https://github.com/cilium/little-vm-helper) in the
CI, you can also use it locally for testing specific kernels. See documentation
[github.com/cilium/tetragon/tests/vmtests](https://github.com/cilium/tetragon/tree/main/tests/vmtests).

## BPF unit tests

To run BPF unit tests, you can use:

```shell
make bpf-test
```

Those tests can be found under
[github.com/cilium/tetragon/bpf/tests](https://github.com/cilium/tetragon/tree/main/bpf/tests).
The framework uses Go tests with `cilium/ebpf` to run those tests, you can use
`BPFGOTESTFLAGS` to add `go test` flags, like `make BPFGOTESTFLAGS="-v"
bpf-test`.

## E2E tests

To run E2E tests, you can use:

```shell
make e2e-test
```

This will build the Tetragon image and use the e2e framework to create a kind
cluster, install Tetragon and run the tests. To not rebuild the image before
running the test, use `E2E_BUILD_IMAGES=0`. You can use `EXTRA_TESTFLAGS` to
add flags to the `go test` command.


## What's next

- See how to [submit your first pull request](/docs/contribution-guide/submitting-a-pull-request/).

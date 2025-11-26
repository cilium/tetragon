// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package consts

const MetricsNamespace = "tetragon"

var (
	ExamplePolicyLabel   = "example-tracingpolicy"
	ExampleKprobeLabel   = "example_kprobe"
	ExampleSyscallLabel  = "example_syscall"
	ExampleNamespace     = "example-namespace"
	ExampleWorkload      = "example-workload"
	ExamplePod           = "example-pod"
	ExampleBinary        = "example-binary"
	ExampleNodeName      = "example-node-name"
	ExampleProcessLabels = []string{ExampleNamespace, ExampleWorkload, ExamplePod, ExampleBinary, ExampleNodeName}
)

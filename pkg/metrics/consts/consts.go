// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package consts

const MetricsNamespace = "tetragon"

var KnownMetricLabelFilters = []string{"namespace", "workload", "pod", "binary"}

var (
	ExamplePolicyLabel   = "example-tracingpolicy"
	ExampleKprobeLabel   = "example_kprobe"
	ExampleSyscallLabel  = "example_syscall"
	ExampleProcessLabels = []string{"example-namespace", "example-workload", "example-pod", "example-binary"}
)

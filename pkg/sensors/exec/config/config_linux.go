// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import "github.com/cilium/tetragon/pkg/kernels"

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	if kernels.EnableV61Progs() {
		return "bpf_execve_event_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_execve_event_v511.o"
	} else if kernels.EnableLargeProgs() {
		return "bpf_execve_event_v53.o"
	}
	return "bpf_execve_event.o"
}

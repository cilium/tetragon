// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// bpf programs and maps for cgrouprate

var (
	cgroupRmdirProg = program.Builder(
		"bpf_cgroup.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_cgroup_rmdir",
		"raw_tracepoint",
	).SetPolicy(base.Execve.Policy)

	cgroupRateMap = program.MapBuilder(
		"cgroup_rate_map", base.Execve, base.Exit, base.Fork, cgroupRmdirProg)

	cgroupRateOptionsMap = program.MapBuilder(
		"cgroup_rate_options_map", base.Execve)
)

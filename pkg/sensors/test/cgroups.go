// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	CgroupMkdir = program.Builder(
		"bpf_cgroup_mkdir.o",
		"cgroup/cgroup_mkdir",
		"raw_tracepoint/cgroup_mkdir",
		"tg_tp_cgrp_mkdir",
		"raw_tracepoint",
	)

	CgroupRmdir = program.Builder(
		"bpf_cgroup_rmdir.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_tp_cgrp_rmdir",
		"raw_tracepoint",
	)

	CgroupRelease = program.Builder(
		"bpf_cgroup_release.o",
		"cgroup/cgroup_release",
		"raw_tracepoint/cgroup_release",
		"tg_tp_cgrp_release",
		"raw_tracepoint",
	)

	CgroupAttachTask = program.Builder(
		"bpf_cgroup_attach_task.o",
		"cgroup/cgroup_attach_task",
		"raw_tracepoint/cgroup_attach_task",
		"tg_tp_cgrp_attach_task",
		"raw_tracepoint",
	)

	/* Cgroup tracking maps */
	CgroupsTrackingMap    = program.MapBuilder("tg_cgrps_tracking_map", CgroupAttachTask)
	CgroupsTrackingMapV53 = program.MapBuilder("tg_cgrps_tracking_map", CgroupAttachTask)
)

func getCgroupsTrackingMap() *program.Map {
	if kernels.EnableLargeProgs() {
		return CgroupsTrackingMapV53
	}
	return CgroupsTrackingMap
}

func getCgroupsPrograms() []*program.Program {
	progs := []*program.Program{
		CgroupAttachTask,
		CgroupMkdir,
		CgroupRmdir,
		CgroupRelease,
	}
	return progs
}

func getCgroupsMaps() []*program.Map {
	maps := []*program.Map{
		getCgroupsTrackingMap(),
	}
	return maps
}

// GetCgroupSensor returns the Cgroups base sensor
func GetCgroupSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "test-sensor-cgroups",
		Progs: getCgroupsPrograms(),
		Maps:  getCgroupsMaps(),
	}
}

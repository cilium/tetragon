// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	CgroupMkdir = program.Builder(
		config.CGroupMkdirObj(),
		"cgroup/cgroup_mkdir",
		"raw_tracepoint/cgroup_mkdir",
		"tg_tp_cgrp_mkdir",
		"raw_tracepoint",
	)

	CgroupRmdir = program.Builder(
		config.CGroupRmdirObj(),
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_tp_cgrp_rmdir",
		"raw_tracepoint",
	)

	CgroupRelease = program.Builder(
		config.CGroupReleaseObj(),
		"cgroup/cgroup_release",
		"raw_tracepoint/cgroup_release",
		"tg_tp_cgrp_release",
		"raw_tracepoint",
	)

	/* Cgroup tracking maps */
	CgroupsTrackingMap = program.MapBuilder("tg_cgrps_tracking_map", CgroupMkdir)
)

func GetCgroupsTrackingMap() *program.Map {
	return CgroupsTrackingMap
}

func getCgroupPrograms() []*program.Program {
	progs := []*program.Program{
		CgroupMkdir,
		CgroupRmdir,
		CgroupRelease,
	}
	return progs
}

func getCgroupMaps() []*program.Map {
	maps := []*program.Map{
		GetCgroupsTrackingMap(),
		program.MapUserFrom(base.ExecveMap),
	}
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		maps = append(maps, program.MapUserFrom(base.RingBufEvents))
	}
	return maps
}

// GetCgroupSensor returns the Cgroups base sensor
func GetCgroupSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "test-sensor-cgroups",
		Progs: getCgroupPrograms(),
		Maps:  getCgroupMaps(),
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
)

const (
	cgroupRateMaxEntries = 32768 // this value could be fine tuned
)

func init() {
	base.RegisterExtensionAtInit("cgroup_rate", registerCgroupRate)
}

func registerCgroupRate(sensor *sensors.Sensor) (*sensors.Sensor, error) {
	if !option.CgroupRateEnabled() {
		return sensor, nil
	}
	/* Cgroup rate data, attached to execve sensor */
	cgroupRateMap.SetMaxEntries(cgroupRateMaxEntries)

	sensor.Progs = append(sensor.Progs, cgroupRmdirProg)
	sensor.Maps = append(sensor.Maps, cgroupRateMap, cgroupRateOptionsMap)
	return sensor, nil
}

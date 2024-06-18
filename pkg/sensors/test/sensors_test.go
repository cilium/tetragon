// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestMapBuildersSingle(t *testing.T) {
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	p1 := program.Builder(
		"bpf_map_test_p1.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p1",
		"kprobe",
	)

	test := func(m1 *program.Map, ty program.MapType) {
		s := &sensors.Sensor{
			Name:   "sensor",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1},
			Policy: "policy",
		}

		getMapPath := func(m *program.Map) string {
			path := "./"
			switch ty {
			case program.MapTypeGlobal:
				// nothing
			case program.MapTypePolicy:
				path = filepath.Join(path, "policy")
			case program.MapTypeSensor:
				path = filepath.Join(path, "policy", "sensor")
			case program.MapTypeProgram:
				path = filepath.Join(path, "policy", "sensor", m.Prog.PinName)
			}
			return filepath.Join(path, m.Name)
		}

		s.Load(bpf.MapPrefixPath())

		assert.Equal(t, getMapPath(m1), m1.PinPath)

		s.Unload()
	}

	test(program.MapBuilder("m1", p1), program.MapTypeGlobal)
	test(program.MapBuilderProgram("m1", p1), program.MapTypeProgram)
	test(program.MapBuilderSensor("m1", p1), program.MapTypeSensor)
	test(program.MapBuilderPolicy("m1", p1), program.MapTypePolicy)
}

func TestMapBuildersMulti(t *testing.T) {
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	p1 := program.Builder(
		"bpf_map_test_p1.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p1",
		"kprobe",
	)

	p2 := program.Builder(
		"bpf_map_test_p2.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p2",
		"kprobe",
	)

	test := func(m1, m2 *program.Map, path1, path2 string) {
		s := &sensors.Sensor{
			Name:   "sensor",
			Progs:  []*program.Program{p1, p2},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		s.Load(bpf.MapPrefixPath())

		assert.Equal(t, path1, m1.PinPath)
		assert.Equal(t, path2, m2.PinPath)

		s.Unload()
	}

	var m1 *program.Map
	var m2 *program.Map

	// NOTE For program.MapBuilderProgram the map takes the
	// first program as the base for its path

	// m1: policy/sensor/p1/m1
	// m2: policy/sensor/p2/m2
	m1 = program.MapBuilderProgram("m1", p1, p2)
	m2 = program.MapBuilderProgram("m2", p2, p1)

	test(m1, m2, "policy/sensor/p1/m1", "policy/sensor/p2/m2")

	// m1: policy/m1
	// m2: policy/m2
	m1 = program.MapBuilderPolicy("m1", p1, p2)
	m2 = program.MapBuilderPolicy("m2", p2, p1)

	test(m1, m2, "policy/m1", "policy/m2")

	// m1: policy/sensor/p1/m1
	// m2: policy/m2
	m1 = program.MapBuilderProgram("m1", p1, p2)
	m2 = program.MapBuilderPolicy("m2", p2, p1)

	test(m1, m2, "policy/sensor/p1/m1", "policy/m2")

	// m1: policy/sensor/p1/m1
	// m2: policy/m2
	m1 = program.MapBuilderSensor("m1", p2, p1)
	m2 = program.MapBuilderPolicy("m2", p2, p1)

	test(m1, m2, "policy/sensor/m1", "policy/m2")
}

func TestPolicyMapPath(t *testing.T) {
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	p1 := program.Builder(
		"bpf_map_test_p1.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p1",
		"kprobe",
	)

	m1 := program.MapBuilderPolicy("m1", p1)

	s := &sensors.Sensor{
		Name:   "sensor",
		Progs:  []*program.Program{p1},
		Maps:   []*program.Map{m1},
		Policy: "policy",
	}

	s.Load(bpf.MapPrefixPath())

	assert.Equal(t, filepath.Join(bpf.MapPrefixPath(), m1.PinPath), program.PolicyMapPath(bpf.MapPrefixPath(), "policy", "m1"))

	s.Unload()
}

func getMaxEntries(t *testing.T, path string) uint32 {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatalf("failed to load map from '%s': %s\n", path, err)
	}

	info, err := m.Info()
	if err != nil {
		t.Fatalf("failed to get map info: %s\n", err)
	}

	return info.MaxEntries
}

func TestMaxEntriesSingle(t *testing.T) {
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	p1 := program.Builder(
		"bpf_map_test_p1.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p1",
		"kprobe",
	)

	m1 := program.MapBuilderPolicy("m1", p1)
	m1.SetMaxEntries(111)

	s := &sensors.Sensor{
		Name:   "sensor",
		Progs:  []*program.Program{p1},
		Maps:   []*program.Map{m1},
		Policy: "policy",
	}

	s.Load(bpf.MapPrefixPath())
	defer s.Unload()

	path := program.PolicyMapPath(bpf.MapPrefixPath(), "policy", "m1")
	assert.Equal(t, uint32(111), getMaxEntries(t, path))
}

func TestMaxEntriesMulti(t *testing.T) {
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	p1 := program.Builder(
		"bpf_map_test_p1.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p1",
		"kprobe",
	)

	p2 := program.Builder(
		"bpf_map_test_p2.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p2",
		"kprobe",
	)

	m1 := program.MapBuilderPolicy("m1", p1, p2)
	m2 := program.MapBuilderSensor("m2", p2, p1)
	m1.SetMaxEntries(111)
	m2.SetMaxEntries(222)

	s := &sensors.Sensor{
		Name:   "sensor",
		Progs:  []*program.Program{p1, p2},
		Maps:   []*program.Map{m1, m2},
		Policy: "policy",
	}

	s.Load(bpf.MapPrefixPath())
	defer s.Unload()

	path1 := filepath.Join(bpf.MapPrefixPath(), m1.PinPath)
	assert.Equal(t, uint32(111), getMaxEntries(t, path1))

	path2 := filepath.Join(bpf.MapPrefixPath(), m2.PinPath)
	assert.Equal(t, uint32(222), getMaxEntries(t, path2))
}

func TestMaxEntriesInnerSingle(t *testing.T) {
	// TODO, we need to check BTF for inner map max entries
	t.Skip()
}

func TestMaxEntriesInnerMulti(t *testing.T) {
	// TODO, we need to check BTF for inner map max entries
	t.Skip()
}

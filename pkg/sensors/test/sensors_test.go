// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package test

import (
	"os"
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

		s.Unload(true)
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

		s.Unload(true)
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

func TestMapMultipleSensors(t *testing.T) {
	// We load 2 sensors sharing same maps and expecting following
	//hierarchy under /sys/fs/bpf/testSensorTest:
	//
	// ./m1                               # global m1 map
	// ./policy
	// ./policy/sensor2
	// ./policy/sensor2/p2
	// ./policy/sensor2/p2/prog
	// ./policy/m2                        # policy m2 map
	// ./policy/sensor1
	// ./policy/sensor1/p1
	// ./policy/sensor1/p1/prog

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

	m11 := program.MapBuilder("m1", p1, p2)
	m12 := program.MapBuilderPolicy("m2", p1, p2)

	s1 := &sensors.Sensor{
		Name:   "sensor1",
		Progs:  []*program.Program{p1},
		Maps:   []*program.Map{m11, m12},
		Policy: "policy",
	}

	m21 := program.MapBuilder("m1", p1, p2)
	m22 := program.MapBuilderPolicy("m2", p1, p2)

	s2 := &sensors.Sensor{
		Name:   "sensor2",
		Progs:  []*program.Program{p2},
		Maps:   []*program.Map{m21, m22},
		Policy: "policy",
	}

	s1.Load(bpf.MapPrefixPath())
	defer s1.Unload(true)

	s2.Load(bpf.MapPrefixPath())
	defer s2.Unload(true)

	assert.Equal(t, m11.PinPath, "m1")
	assert.Equal(t, m12.PinPath, "policy/m2")
	assert.Equal(t, m11.PinPath, m21.PinPath)
	assert.Equal(t, m12.PinPath, m22.PinPath)
}

func TestMapUser(t *testing.T) {
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
	p3 := program.Builder(
		"bpf_map_test_p3.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p3",
		"kprobe",
	)
	opts := program.MapOpts{
		Type:  program.MapTypeGlobal,
		Owner: false,
	}

	var err error

	// Create sensor with user map (via MapUser builder) and make sure
	// it's properly loaded
	t.Run("ok_opts", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		// user map
		m1User := program.MapUser("m1", p2)

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		defer s2.Unload(true)
		assert.NoError(t, err)
	})

	// Create sensor with user map (via opts) and make sure it's
	// properly loaded
	t.Run("ok_builder", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		// user map
		m1User := program.MapBuilderOpts("m1", opts, p2)

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		defer s2.Unload(true)
		assert.NoError(t, err)
	})

	// Create sensor with user map (via MapUser builder) and make sure
	// it's properly loaded
	t.Run("ok_from", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		// user map
		m1User := program.MapUserFrom(m1)

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		defer s2.Unload(true)
		assert.NoError(t, err)
	})

	// Create sensor with user map with wrong name (no existing pinned
	// map file) and make sure the sensor fails to load
	t.Run("fail_name", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1, p2)

		// user map with wrong name
		m2 := program.MapBuilderOpts("non-existing", opts, p1, p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.Error(t, err)
		if err == nil {
			defer s1.Unload(true)
		}
	})

	// Create sensor with user map with different max entries setup
	// from real owner map and make sure the sensor fails to load
	t.Run("fail_max", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m1.SetMaxEntries(10)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1},
			Policy: "policy",
		}

		// user map with extra max setup
		m1User := program.MapBuilderOpts("m1", opts, p2)
		m1User.SetMaxEntries(100)

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		defer s2.Unload(true)
		assert.Error(t, err)
	})

	// Create sensor with user map with different spec from real owner
	// map and make sure the sensor fails to load
	t.Run("fail_spec", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1},
			Policy: "policy",
		}

		// The bpf_map_test_p3 has map with same name and different
		// value type, so we should fail to load it.
		m1User := program.MapBuilderOpts("m1", opts, p3)

		s3 := &sensors.Sensor{
			Name:   "sensor3",
			Progs:  []*program.Program{p3},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s3.Load(bpf.MapPrefixPath())
		defer s3.Unload(true)
		assert.Error(t, err)
	})
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

	s.Unload(true)
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
	defer s.Unload(true)

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
	defer s.Unload(true)

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

func TestCleanup(t *testing.T) {
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
	p3 := program.Builder(
		"bpf_map_test_p3.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"p3",
		"badtype",
	)

	var err error

	verifyRemoved := func(files ...string) {
		for _, f := range files {
			_, err := os.Stat(filepath.Join(bpf.MapPrefixPath(), f))
			t.Logf("Removed checking path: '%s'\n", f)
			assert.Error(t, err)
		}
	}

	verifyExists := func(files ...string) {
		for _, f := range files {
			_, err := os.Stat(filepath.Join(bpf.MapPrefixPath(), f))
			t.Logf("Exists checking path: '%s'\n", f)
			assert.NoError(t, err)
		}
	}

	t.Run("single_ok", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		s1.Unload(true)
		verifyRemoved("m1", "m2", "policy")
	})

	t.Run("multi_ok", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)
		err = s2.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		s1.Unload(true)
		verifyRemoved("policy/sensor1")

		s2.Unload(true)
		verifyRemoved("m1", "m2", "policy")
	})

	t.Run("map_fail", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1, p2)
		// map with wrong name
		m2 := program.MapBuilder("non-existing", p1, p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.Error(t, err)
		if err == nil {
			defer s1.Unload(true)
		}

		verifyRemoved("m1", "m2", "policy")
	})

	t.Run("prog_fail", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1, p3)
		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1},
			Policy: "policy",
		}

		s3 := &sensors.Sensor{
			Name:   "sensor3",
			Progs:  []*program.Program{p3},
			Maps:   []*program.Map{m1},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		err = s3.Load(bpf.MapPrefixPath())
		assert.Error(t, err)

		s1.Unload(true)
		verifyRemoved("m1", "policy")
	})

	t.Run("namespace", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:      "sensor1",
			Progs:     []*program.Program{p1},
			Maps:      []*program.Map{m1, m2},
			Policy:    "policy",
			Namespace: "ns1",
		}

		s2 := &sensors.Sensor{
			Name:      "sensor2",
			Progs:     []*program.Program{p2},
			Maps:      []*program.Map{m1, m2},
			Policy:    "policy",
			Namespace: "ns2",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)
		err = s2.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		s1.Unload(true)
		verifyRemoved("ns1:policy")
		verifyExists("m1", "m2")

		s2.Unload(true)
		verifyRemoved("ns2:policy")
		verifyRemoved("m1", "m2")
	})

	// Create sensor (s2) with user map and make sure the map (m1)
	// stays in place (unpinned) after the sensor s2 is unloaded
	// and s1 unload takes all out.
	t.Run("user_unload", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1)
		m2 := program.MapBuilder("m2", p2)

		s1 := &sensors.Sensor{
			Name:   "sensor1",
			Progs:  []*program.Program{p1},
			Maps:   []*program.Map{m1, m2},
			Policy: "policy",
		}

		// user map
		m1User := program.MapUser("m1", p2)

		s2 := &sensors.Sensor{
			Name:   "sensor2",
			Progs:  []*program.Program{p2},
			Maps:   []*program.Map{m1User},
			Policy: "policy",
		}

		err = s1.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		assert.NoError(t, err)

		err = s2.Unload(true)
		assert.NoError(t, err)

		// s1 is still loaded and we just unloaded s2 with m1 being user map,
		// m1 should be untouched
		verifyExists("m1")

		// ... but sensor2 should get removed
		verifyRemoved("policy/sensor2")

		err = s1.Unload(true)
		assert.NoError(t, err)

		// s1 unload takes down everything
		verifyRemoved("policy", "m1", "m2")
	})
}

func TestNamespace(t *testing.T) {
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

	var err error

	// Create sensor with user map (via MapUser builder) and make sure
	// it's properly loaded
	t.Run("namespace", func(t *testing.T) {
		m1 := program.MapBuilder("m1", p1, p2)
		m2 := program.MapBuilderPolicy("m2", p1, p2)

		s1 := &sensors.Sensor{
			Name:      "sensor1",
			Progs:     []*program.Program{p1},
			Maps:      []*program.Map{m1, m2},
			Policy:    "policy",
			Namespace: "ns1",
		}

		s2 := &sensors.Sensor{
			Name:      "sensor2",
			Progs:     []*program.Program{p2},
			Maps:      []*program.Map{m1, m2},
			Policy:    "policy",
			Namespace: "ns2",
		}

		err = s1.Load(bpf.MapPrefixPath())
		defer s1.Unload(true)
		assert.NoError(t, err)

		err = s2.Load(bpf.MapPrefixPath())
		defer s2.Unload(true)
		assert.NoError(t, err)

		assert.Equal(t, "ns1:policy/sensor1/p1", p1.PinPath)
		assert.Equal(t, "ns2:policy/sensor2/p2", p2.PinPath)
		assert.Equal(t, "m1", m1.PinPath)
		// first loaded sensor 'owns' the map
		assert.Equal(t, "ns1:policy/m2", m2.PinPath)
	})
}

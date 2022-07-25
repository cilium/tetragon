// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type SensorProg struct {
	Name  string
	Type  ebpf.ProgramType
	NotIn bool
}

type SensorMap struct {
	Name  string
	Progs []uint
}

func findMapForProg(coll *program.LoadedCollection, nam string, p *program.LoadedProgram, t *testing.T) *program.LoadedMap {
	for name, m := range coll.Maps {
		if nam != name {
			continue
		}
		for _, id := range p.MapIDs {
			if m.ID == id {
				return m
			}
		}
	}
	return nil
}

type prog struct {
	name string
	prog *program.LoadedProgram
	coll *program.LoadedCollection
	mark bool
}

func findProgram(cache []*prog, name string, typ ebpf.ProgramType, t *testing.T) *prog {
	for _, c := range cache {
		if c.prog.Type != typ {
			continue
		}
		if c.name == name {
			return c
		}
	}
	return nil
}

func CheckSensorLoad(sensors []*sensors.Sensor, sensorMaps []SensorMap, sensorProgs []SensorProg, t *testing.T) {

	var cache []*prog

	// make programs cache 'name/type/coll'
	for _, sensor := range sensors {
		for _, load := range sensor.Progs {
			c := load.LC
			for n, p := range c.Programs {
				c := &prog{name: n, prog: p, coll: c, mark: false}
				cache = append(cache, c)
			}
		}
	}

	// check that we loaded expected programs
	for _, tp := range sensorProgs {
		c := findProgram(cache, tp.Name, tp.Type, t)
		if c == nil {
			t.Fatalf("could not find program %v in sensor", tp.Name)
		}
		c.mark = true
		t.Logf("Found prog %v type %s\n", c.name, c.prog.Type)
	}

	var extra bool

	// check that we did not load anything else
	for _, c := range cache {
		if !c.mark {
			t.Logf("found extra program loaded: %v type %s", c.name, c.prog.Type)
			extra = true
		}
	}

	if extra {
		t.Fatalf("found extra program loaded")
	}

	// check user provided maps
	for _, tm := range sensorMaps {
		var sharedId ebpf.MapID

		t.Logf("Checking map %v\n", tm.Name)

		for _, c := range cache {
			c.mark = false
		}

		// check that tm.Progs programs DO share the map
		for _, idx := range tm.Progs {
			tp := sensorProgs[idx]

			c := findProgram(cache, tp.Name, tp.Type, t)
			if c == nil {
				t.Fatalf("could not find program %v in sensor\n", tp.Name)
			}

			m := findMapForProg(c.coll, tm.Name, c.prog, t)
			if m == nil {
				t.Fatalf("could not find map %v in program %v\n", tm.Name, tp.Name)
			}

			t.Logf("\tFound map %v id %v in prog %v\n", tm.Name, m.ID, tp.Name)

			if sharedId == 0 {
				sharedId = m.ID
			}

			if m.ID != sharedId {
				t.Fatalf("map %v has wrong shared id %v != %v\n", tm.Name, m.ID, sharedId)
			}
			c.mark = true
		}

		// check that rest of the loaded programs DO NOT share the map
		for _, c := range cache {
			if c.mark {
				continue
			}

			m := findMapForProg(c.coll, tm.Name, c.prog, t)
			if m == nil {
				continue
			}

			if m.ID == sharedId {
				t.Fatalf("Map %s[%d] is shared also with program %s", tm.Name, m.ID, c.name)
			}
		}
	}
}

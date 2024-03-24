// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type ProgMatch = int

const (
	ProgMatchFull    ProgMatch = iota // ==
	ProgMatchPartial                  // strings.Contains()
)

type SensorProg struct {
	Name  string
	Type  ebpf.ProgramType
	NotIn bool
	Match ProgMatch
}

type SensorMap struct {
	Name  string
	Progs []uint
}

func findMapForProg(coll *program.LoadedCollection, nam string, p *program.LoadedProgram) *program.LoadedMap {
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

func findProgram(cache []*prog, name string, typ ebpf.ProgramType, match ProgMatch) *prog {
	for _, c := range cache {
		if c.prog.Type != typ {
			continue
		}
		switch match {
		case ProgMatchPartial:
			if strings.Contains(c.name, name) {
				return c
			}
		case ProgMatchFull:
			if c.name == name {
				return c
			}
		}
	}
	return nil
}

func mergeSensorMaps(t *testing.T, maps1, maps2 []SensorMap, progs1, progs2 []SensorProg) ([]SensorMap, []SensorProg) {
	// we take maps1,progs1 and merge in maps2,progs2
	mapsReturn := maps1
	progsReturn := progs1

	var idxList []uint
	idx := uint(len(progsReturn))

	// merge in progs2
	for _, p2 := range progs2 {
		// do maps share the same program
		for _, p := range progsReturn {
			if p.Name == p2.Name && p.Type == p2.Type {
				t.Fatalf("merge fail: program '%s' in both maps", p.Name)
			}
		}

		progsReturn = append(progsReturn, p2)
		idxList = append(idxList, idx)
		idx++
	}

	// merge in maps2
	for _, m2 := range maps2 {
		shared := false

		// do we have shared map
		for i1, m1 := range maps1 {
			// shared map, add progs2 into it
			if m1.Name == m2.Name {
				for _, ip := range m2.Progs {
					mapsReturn[i1].Progs = append(mapsReturn[i1].Progs, idxList[ip])
				}
				shared = true
				break
			}
		}

		if shared {
			continue
		}

		// new map, merge it in with proper indexes
		var newProgs []uint

		m := m2
		for _, i := range m.Progs {
			newProgs = append(newProgs, idxList[i])
		}

		m.Progs = newProgs
		mapsReturn = append(mapsReturn, m)
	}

	return mapsReturn, progsReturn
}

func mergeInBaseSensorMaps(t *testing.T, sensorMaps []SensorMap, sensorProgs []SensorProg) ([]SensorMap, []SensorProg) {
	var baseProgs = []SensorProg{
		0: SensorProg{Name: "event_execve", Type: ebpf.TracePoint},
		1: SensorProg{Name: "event_exit", Type: ebpf.Kprobe, Match: ProgMatchPartial},
		2: SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
		3: SensorProg{Name: "execve_send", Type: ebpf.TracePoint},
		4: SensorProg{Name: "tg_kp_bprm_committing_creds", Type: ebpf.Kprobe},
		5: SensorProg{Name: "execve_rate", Type: ebpf.TracePoint},
	}

	var baseMaps = []SensorMap{
		// all programs
		SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4}},
		SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3}},

		// all but event_execve
		SensorMap{Name: "execve_map_stats", Progs: []uint{1, 2}},

		// event_execve
		SensorMap{Name: "tg_conf_map", Progs: []uint{0}},

		// event_wake_up_new_task
		SensorMap{Name: "execve_val", Progs: []uint{2}},

		// event_execve and tg_kp_bprm_committing_creds
		SensorMap{Name: "tg_execve_joined_info_map", Progs: []uint{0, 4}},
		SensorMap{Name: "tg_execve_joined_info_map_stats", Progs: []uint{0, 4}},
	}

	return mergeSensorMaps(t, sensorMaps, baseMaps, sensorProgs, baseProgs)
}

func CheckSensorLoad(sensors []*sensors.Sensor, sensorMaps []SensorMap, sensorProgs []SensorProg, t *testing.T) {

	sensorMaps, sensorProgs = mergeInBaseSensorMaps(t, sensorMaps, sensorProgs)

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
		c := findProgram(cache, tp.Name, tp.Type, tp.Match)
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

			c := findProgram(cache, tp.Name, tp.Type, tp.Match)
			if c == nil {
				t.Fatalf("could not find program %v in sensor\n", tp.Name)
			}

			m := findMapForProg(c.coll, tm.Name, c.prog)
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

			m := findMapForProg(c.coll, tm.Name, c.prog)
			if m == nil {
				continue
			}

			if m.ID == sharedId {
				t.Fatalf("Error: Map %s[%d] is shared also with program %s", tm.Name, m.ID, c.name)
			}
		}
	}
}

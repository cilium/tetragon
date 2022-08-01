package sensors

import (
	"testing"

	"github.com/cilium/ebpf"
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

func findMapForProg(coll *ebpf.Collection, nam string, p *ebpf.Program, t *testing.T) *ebpf.Map {
	for name, m := range coll.Maps {
		if nam != name {
			continue
		}

		var err error
		var pInfo *ebpf.ProgramInfo
		var mInfo *ebpf.MapInfo

		pInfo, err = p.Info()
		if err != nil {
			t.Fatalf("program.Info failed: %v\n", err)
		}

		mInfo, err = m.Info()
		if err != nil {
			t.Fatalf("map.Info failed: %v\n", err)
		}

		mapIds, ok := pInfo.MapIDs()
		if !ok {
			t.Fatalf("can't get map ids\n")
		}

		for _, mapId := range mapIds {
			mId, avail := mInfo.ID()

			if avail && mId == mapId {
				return m
			}

		}
	}
	return nil
}

type prog struct {
	name string
	prog *ebpf.Program
	coll *ebpf.Collection
	mark bool
}

func findProgram(cache []*prog, name string, typ ebpf.ProgramType, t *testing.T) *prog {
	for _, c := range cache {
		if c.mark {
			continue
		}
		if c.prog.Type() != typ {
			continue
		}
		if c.name == name {
			return c
		}
	}
	return nil
}

func CheckSensorLoad(colls []*ebpf.Collection, sensorMaps []SensorMap, sensorProgs []SensorProg, t *testing.T) {

	var cache []*prog

	// make programs cache 'name/type/coll'
	for _, c := range colls {
		for n, p := range c.Programs {
			c := &prog{name: n, prog: p, coll: c, mark: false}
			cache = append(cache, c)
		}
	}

	// check that we loaded expected programs
	for _, tp := range sensorProgs {
		c := findProgram(cache, tp.Name, tp.Type, t)
		if c == nil {
			t.Fatalf("could not find program %v in sensor", tp.Name)
		}
		c.mark = true
		t.Logf("Found prog %v type %s\n", c.name, c.prog.Type())
	}

	// check that we did not load anything else
	for _, c := range cache {
		if !c.mark {
			t.Fatalf("found extra program loaded: %v type %s", c.name, c.prog.Type())
		}
	}

	// check user provided maps
	for _, tm := range sensorMaps {
		var sharedId ebpf.MapID

		t.Logf("Checking map %v\n", tm.Name)

		for _, c := range cache {
			c.mark = false
		}

		// check that tm.Progs  programs share the map
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

			id, err := m.ID()
			if err != nil {
				t.Fatalf("failed to get map id: %v\n", err)
			}

			t.Logf("\tFound map %v id %v in prog %v\n", tm.Name, id, tp.Name)

			if sharedId == 0 {
				sharedId = id
			}

			if id != sharedId {
				t.Fatalf("map %v has wrong shared id %v != %v\n", tm.Name, id, sharedId)
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

			id, err := m.ID()
			if err != nil {
				t.Fatalf("failed to get map id: %v\n", err)
			}

			if id == sharedId {
				t.Fatalf("Map %s[%d] is shared also with program %s", tm.Name, id, c.name)
			}
		}
	}
}

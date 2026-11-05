package btf

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/defaults"
)

func TestEnumBase(t *testing.T) {
	if err := InitCachedBTF(defaults.DefaultTetragonLib, defaults.DefaultBTFFile); err != nil {
		t.Fatalf("InitCachedBTF failed: %v", err)
	}

	var err error
	var spec *btf.Spec

	spec, err = NewBTF()
	if err != nil {
		t.Fatalf("NewBTF failed: %v\n", err)
	}

	InitEnumMap(spec)

	var v uint64
	var name string

	// find perf_sw_context enum value globally

	v, err = EnumFind("perf_sw_context")
	if err != nil {
		t.Fatalf("EnumFind failed: %v\n", err)
	}
	if v != 1 {
		t.Fatalf("EnumFind returned wrong value: %v\n", v)
	}

	// find perf_sw_context enum value in perf_event_task_context enum

	v, err = EnumFindByName("perf_event_task_context", "perf_sw_context")
	if err != nil {
		t.Fatalf("EnumFindByName failed: %v\n", err)
	}
	if v != 1 {
		t.Fatalf("EnumFind returned wrong value: %v\n", v)
	}

	// find enum name for value '1' in perf_event_task_context enum

	name, err = EnumFindByValue("perf_event_task_context", 1)
	if err != nil {
		t.Fatalf("EnumFindByValue failed: %v\n", err)
	}
	if name != "perf_sw_context" {
		t.Fatalf("EnumFindByValue returned wrong value: %v\n", name)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Globals are the variables that should be changed at program load time
// to constants.
type Globals map[string]int64

// StructToGlobals is a convenience function to be able to write the
// program's globals using a struct rather than a map.
func StructToGlobals(st interface{}) Globals {
	globals := make(map[string]int64)
	typ := reflect.TypeOf(st)
	if typ.Kind() != reflect.Struct {
		panic(fmt.Sprintf("StructToGlobals: %T is not a struct", st))
	}
	val := reflect.ValueOf(st)

	for i := 0; i < typ.NumField(); i++ {
		fld := typ.Field(i)
		switch fld.Type.Kind() {
		case reflect.Int16, reflect.Int32, reflect.Int64:
			globals[fld.Name] = int64(val.Field(i).Int())
		case reflect.Uint16, reflect.Uint32, reflect.Uint64:
			globals[fld.Name] = int64(val.Field(i).Uint())
		default:
			panic(fmt.Sprintf("StructToGlobals: %T.%s is not supported type", st, fld.Name))
		}
	}
	return globals
}

// replaceGlobals replaces all map loads from .rodata with immediate dword
// loads, effectively performing those map lookups in the loader. This is done
// for compatibility with kernels that don't support static data maps yet.
func replaceGlobals(spec *ebpf.CollectionSpec) error {
	data, err := getRodata(spec)
	if err != nil {
		// No static data, nothing to replace.
		return nil
	}

	for _, prog := range spec.Programs {
		for i, ins := range prog.Instructions {
			if ins.IsLoadFromMap() && ins.Src == asm.PseudoMapValue && ins.Reference == ".rodata" {
				// Read the constant from the data section. Constants on this side need to be
				// 64-bit since we cannot deduce the size of the variable.
				off := uint32(uint64(ins.Constant) >> 32)
				imm := int64(spec.ByteOrder.Uint64(data[off : off+8]))

				// Replace the map load with an immediate dword load. Since we're replacing
				// a map load, we'll need to do a dword load to match the bytecode size.
				//
				prog.Instructions[i] = asm.LoadImm(ins.Dst, imm, asm.DWord)
			}
		}
	}

	// Drop the .rodata section so this can be loaded on older kernels.
	delete(spec.Maps, ".rodata")

	return nil
}

// getRodata gets the contents of the first entry in the .rodata map.
// This map holds all static data used in the ELF's programs.
func getRodata(spec *ebpf.CollectionSpec) ([]byte, error) {
	data := spec.Maps[".rodata"]
	if data == nil {
		return nil, errors.New("spec doesn't contain a .rodata section")
	}

	if dl := len(data.Contents); dl != 1 {
		return nil, fmt.Errorf("expected map .data to have 1 entry, found %d", dl)
	}

	val := data.Contents[0].Value
	out, ok := (data.Contents[0].Value).([]byte)
	if !ok {
		return nil, fmt.Errorf(".rodata's Value must be a byte slice, got %T", val)
	}

	return out, nil
}

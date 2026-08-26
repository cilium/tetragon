// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"slices"

	"maps"
)

type BPFDbgEnum struct {
	*SliceEnum
	areaMap map[string]uint8
}

func NewBPFDbgEnum(allowedMap map[string]uint8) *BPFDbgEnum {
	allowedVals := slices.Collect(maps.Keys(allowedMap))
	allowedVals = append(allowedVals, "all")
	// Make the slice stable to generate stable flags documentation.
	// Since we are collecting from a map, we need to guarantee it.
	slices.Sort(allowedVals)
	enum, _ := NewSliceEnum(allowedVals, nil)

	return &BPFDbgEnum{
		SliceEnum: enum,
		areaMap:   allowedMap,
	}
}

func (e *BPFDbgEnum) ToBPFConfig() uint8 {
	if slices.Contains(e.Values, "all") {
		return 0xff
	}
	var cfgVal uint8
	for _, v := range e.Values {
		cfgVal |= e.areaMap[v]
	}
	return cfgVal
}

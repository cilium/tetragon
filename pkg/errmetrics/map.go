// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const UnknownFname = "<unknown>"

type Map struct {
	*ebpf.Map
}

func OpenMap(fname string) (Map, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})

	if err != nil {
		return Map{}, err
	}

	return Map{m}, err
}

// NB: should match bpf/lib/bpf_errmetrics.h:errmetrics_key
type MapKey struct {
	Err      uint16
	FileID   uint8
	Pad1     uint8
	LineNR   uint16
	Pad2     uint16
	HelperID uint32
}

type MapVal = uint32

type DumpEntry struct {
	Location string
	Error    string
	Count    int
}

func (m Map) Dump() ([]DumpEntry, error) {
	var key MapKey
	var val []MapVal
	var ret []DumpEntry

	fileIDs, err := GetFileIDs()
	if err != nil {
		return nil, err
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fname, ok := fileIDs[int(key.FileID)]
		if !ok {
			fname = UnknownFname
		}
		helperFunc, err := asm.BuiltinFuncForPlatform(runtime.GOOS, key.HelperID)
		if err != nil {
			helperFunc = asm.FnUnspec
		}
		count := 0
		for _, v := range val {
			count += int(v)
		}
		ret = append(ret, DumpEntry{
			Location: fmt.Sprintf("%s@bpf/%s:%d", helperFunc.String(), fname, key.LineNR),
			Error:    fmt.Sprintf("%s (%d)", GetErrorMessage(key.Err), key.Err),
			Count:    count,
		})
	}

	return ret, nil
}

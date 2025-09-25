// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
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
	HelperFunc string `json:"helper_func,omitempty"`
	FileName   string `json:"file_name,omitempty"`
	LineNumber uint16 `json:"line_numer,omitempty"`
	ErrorName  string `json:"error_name,omitempty"`
	Error      uint16 `json:"error,omitempty"`
	Count      int    `json:"count,omitempty"`
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
		helperFunc, _ := asm.BuiltinFuncForPlatform(runtime.GOOS, key.HelperID)
		var helperFuncName string
		if helperFunc != asm.FnUnspec {
			helperFuncName = helperFunc.String()
		}
		count := 0
		for _, v := range val {
			count += int(v)
		}
		ret = append(ret, DumpEntry{
			HelperFunc: helperFuncName,
			FileName:   fname,
			LineNumber: key.LineNR,
			Error:      key.Err,
			ErrorName:  GetErrorMessage(key.Err),
			Count:      count,
		})
	}

	return ret, nil
}

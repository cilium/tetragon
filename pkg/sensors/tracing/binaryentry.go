// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"github.com/cilium/ebpf"
)

type BinaryMapKey struct {
	PathName [256]byte
}

type BinaryMapValue struct {
	Id uint32
}

func writeBinaryMap(m *ebpf.Map, id uint32, path string) error {
	p := [256]byte{0}
	copy(p[:], path)

	k := &BinaryMapKey{
		PathName: p,
	}
	v := &BinaryMapValue{
		Id: uint32(id),
	}
	return m.Update(k, v, ebpf.UpdateAny)
}

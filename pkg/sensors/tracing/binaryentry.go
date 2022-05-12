// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
)

type BinaryMapKey struct {
	PathName [256]byte
}

func (k *BinaryMapKey) String() string             { return fmt.Sprintf("pathname: %s", string(k.PathName[:])) }
func (k *BinaryMapKey) NewValue() bpf.MapValue     { return &BinaryMapValue{} }
func (k *BinaryMapKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *BinaryMapKey) DeepCopyMapKey() bpf.MapKey { return &BinaryMapKey{} }

type BinaryMapValue struct {
	Id uint32
}

func (v *BinaryMapValue) String() string                 { return fmt.Sprintf("ID: %d", v.Id) }
func (v *BinaryMapValue) NewValue() bpf.MapValue         { return &BinaryMapValue{} }
func (v *BinaryMapValue) GetValuePtr() unsafe.Pointer    { return unsafe.Pointer(v) }
func (v *BinaryMapValue) DeepCopyMapValue() bpf.MapValue { return &BinaryMapValue{} }

func writeBinaryMap(id int, path string, m *bpf.Map) error {
	p := [256]byte{0}
	copy(p[:], path)

	k := &BinaryMapKey{
		PathName: p,
	}
	v := &BinaryMapValue{
		Id: uint32(id),
	}
	err := m.Update(k, v)
	return err
}

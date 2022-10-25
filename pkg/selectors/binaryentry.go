// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package selectors

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/base"
)

const (
	maxMapRetries = 4
	mapRetryDelay = 1
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

func WriteBinaryMap(id uint32, path string) error {
	mapDir := bpf.MapPrefixPath()
	m, err := bpf.OpenMap(filepath.Join(mapDir, base.NamesMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, base.NamesMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}

	defer m.Close()

	p := [256]byte{0}
	copy(p[:], path)

	k := &BinaryMapKey{
		PathName: p,
	}
	v := &BinaryMapValue{
		Id: uint32(id),
	}
	return m.Update(k, v)
}

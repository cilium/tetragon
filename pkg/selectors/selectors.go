// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package selectors

import (
	"encoding/binary"
)

type KernelSelectorState struct {
	off uint32     // offset into encoding
	e   [4096]byte // kernel encoding of selectors

	// valueMaps are used to populate value maps for InMap and NotInMap operators
	valueMaps []map[[8]byte]struct{}
}

func (k *KernelSelectorState) Buffer() [4096]byte {
	return k.e
}

func (k *KernelSelectorState) ValueMaps() []map[[8]byte]struct{} {
	return k.valueMaps
}

func WriteSelectorInt32(k *KernelSelectorState, v int32) {
	binary.LittleEndian.PutUint32(k.e[k.off:], uint32(v))
	k.off += 4
}

func WriteSelectorUint32(k *KernelSelectorState, v uint32) {
	binary.LittleEndian.PutUint32(k.e[k.off:], v)
	k.off += 4
}

func WriteSelectorInt64(k *KernelSelectorState, v int64) {
	binary.LittleEndian.PutUint64(k.e[k.off:], uint64(v))
	k.off += 8
}

func WriteSelectorUint64(k *KernelSelectorState, v uint64) {
	binary.LittleEndian.PutUint64(k.e[k.off:], v)
	k.off += 8
}

func WriteSelectorLength(k *KernelSelectorState, loff uint32) {
	diff := k.off - loff
	binary.LittleEndian.PutUint32(k.e[loff:], diff)
}

func WriteSelectorByteArray(k *KernelSelectorState, b []byte, size uint32) {
	for l := uint32(0); l < size; l++ {
		k.e[k.off+l] = b[l]
	}
	k.off += size
}

func AdvanceSelectorLength(k *KernelSelectorState) uint32 {
	off := k.off
	k.off += 4
	return off
}

func ArgSelectorValue(v string) ([]byte, uint32) {
	b := []byte(v)
	return b, uint32(len(b))
}

func (k *KernelSelectorState) newValueMap() (uint32, map[[8]byte]struct{}) {
	mapid := len(k.valueMaps)
	k.valueMaps = append(k.valueMaps, map[[8]byte]struct{}{})
	return uint32(mapid), k.valueMaps[mapid]
}

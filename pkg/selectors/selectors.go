// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package selectors

import (
	"encoding/binary"
	"sync"
)

// as we use a single names_map for all kprobes, so we have to use
// a global variable to assign values to binary names
var (
	binMu  sync.Mutex
	binIdx uint32 = 1
	// contains all entries for the names_map
	binVals = make(map[string]uint32)
)

type MatchBinariesMappings struct {
	op          uint32
	selNamesMap map[uint32]uint32 // these will be used for the sel_names_map
}

func (k *MatchBinariesMappings) GetBinSelNamesMap() map[uint32]uint32 {
	return k.selNamesMap
}

type KernelLpmTrie4 struct {
	prefix uint32
	addr   uint32
}

type KernelLpmTrie6 struct {
	prefix uint32
	addr   [16]byte
}

type ValueMap struct {
	Data map[[8]byte]struct{}
}

type ValueReader interface {
	Read(value string) ([]uint32, error)
}

type KernelSelectorState struct {
	off uint32     // offset into encoding
	e   [4096]byte // kernel encoding of selectors

	// valueMaps are used to populate value maps for InMap and NotInMap operators
	valueMaps []ValueMap

	// addr4Maps are used to populate IPv4 address LpmTrie maps for sock and skb operators
	addr4Maps []map[KernelLpmTrie4]struct{}

	// addr6Maps are used to populate IPv6 address LpmTrie maps for sock and skb operators
	addr6Maps []map[KernelLpmTrie6]struct{}

	matchBinaries map[int]*MatchBinariesMappings // matchBinaries mappings (one per selector)
	newBinVals    map[uint32]string              // these should be added in the names_map

	listReader ValueReader
}

func NewKernelSelectorState(listReader ValueReader) *KernelSelectorState {
	return &KernelSelectorState{
		matchBinaries: make(map[int]*MatchBinariesMappings),
		newBinVals:    make(map[uint32]string),
		listReader:    listReader,
	}
}

func (k *KernelSelectorState) SetBinaryOp(selIdx int, op uint32) {
	// init a new entry (if needed)
	if _, ok := k.matchBinaries[selIdx]; !ok {
		k.matchBinaries[selIdx] = &MatchBinariesMappings{
			selNamesMap: make(map[uint32]uint32),
		}
	}
	k.matchBinaries[selIdx].op = op
}

func (k *KernelSelectorState) GetBinaryOp(selIdx int) uint32 {
	return k.matchBinaries[selIdx].op
}

func (k *KernelSelectorState) AddBinaryName(selIdx int, binary string) {
	binMu.Lock()
	defer binMu.Unlock()
	idx, ok := binVals[binary]
	if ok {
		k.matchBinaries[selIdx].selNamesMap[idx] = 1
		return
	}

	idx = binIdx
	binIdx++
	binVals[binary] = idx                        // global map of all names_map entries
	k.newBinVals[idx] = binary                   // new names_map entries that we should add
	k.matchBinaries[selIdx].selNamesMap[idx] = 1 // value in the per-selector names_map (we ignore the value)
}

func (k *KernelSelectorState) GetNewBinaryMappings() map[uint32]string {
	return k.newBinVals
}

func (k *KernelSelectorState) GetBinSelNamesMap() map[int]*MatchBinariesMappings {
	return k.matchBinaries
}

func (k *KernelSelectorState) Buffer() [4096]byte {
	return k.e
}

func (k *KernelSelectorState) ValueMaps() []ValueMap {
	return k.valueMaps
}

func (k *KernelSelectorState) Addr4Maps() []map[KernelLpmTrie4]struct{} {
	return k.addr4Maps
}

func (k *KernelSelectorState) Addr6Maps() []map[KernelLpmTrie6]struct{} {
	return k.addr6Maps
}

// ValueMapsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) ValueMapsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.valueMaps {
		if l := len(vm.Data); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

// Addr4MapsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) Addr4MapsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.addr4Maps {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

// Addr6MapsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) Addr6MapsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.addr6Maps {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
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

func WriteSelectorOffsetUint32(k *KernelSelectorState, loff uint32, val uint32) {
	binary.LittleEndian.PutUint32(k.e[loff:], val)
}

func GetCurrentOffset(k *KernelSelectorState) uint32 {
	return k.off
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

func (k *KernelSelectorState) newValueMap() (uint32, ValueMap) {
	mapid := len(k.valueMaps)
	vm := ValueMap{}
	vm.Data = make(map[[8]byte]struct{})
	k.valueMaps = append(k.valueMaps, vm)
	return uint32(mapid), k.valueMaps[mapid]
}

func (k *KernelSelectorState) createAddr4Map() map[KernelLpmTrie4]struct{} {
	return map[KernelLpmTrie4]struct{}{}
}

func (k *KernelSelectorState) insertAddr4Map(addr4map map[KernelLpmTrie4]struct{}) uint32 {
	mapid := len(k.addr4Maps)
	k.addr4Maps = append(k.addr4Maps, addr4map)
	return uint32(mapid)
}

func (k *KernelSelectorState) createAddr6Map() map[KernelLpmTrie6]struct{} {
	return map[KernelLpmTrie6]struct{}{}
}

func (k *KernelSelectorState) insertAddr6Map(addr6map map[KernelLpmTrie6]struct{}) uint32 {
	mapid := len(k.addr6Maps)
	k.addr6Maps = append(k.addr6Maps, addr6map)
	return uint32(mapid)
}

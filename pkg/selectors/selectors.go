// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package selectors

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/kernels"
)

type KernelLPMTrie4 struct {
	prefixLen uint32
	addr      uint32
}

type KernelLPMTrie6 struct {
	prefixLen uint32
	addr      [16]byte
}

type ValueMap struct {
	Data map[[8]byte]struct{}
}

type ValueReader interface {
	Read(value string, ty uint32) ([]uint32, error)
}

const (
	stringMapsKeyIncSize      = 24
	StringMapsNumSubMaps      = 11
	StringMapsNumSubMapsSmall = 8
	MaxStringMapsSize         = 4096 + 2
	StringPrefixMaxLength     = 256
	StringPostfixMaxLength    = 128

	// Maps with key string length <256 only require a single byte
	// to store string length. Maps with key string length >=256
	// require two bytes to store string length.
	stringMapSize0  = 1*stringMapsKeyIncSize + 1
	stringMapSize1  = 2*stringMapsKeyIncSize + 1
	stringMapSize2  = 3*stringMapsKeyIncSize + 1
	stringMapSize3  = 4*stringMapsKeyIncSize + 1
	stringMapSize4  = 5*stringMapsKeyIncSize + 1
	stringMapSize5  = 6*stringMapsKeyIncSize + 1
	stringMapSize6  = 256 + 2
	stringMapSize7  = 512 + 2
	stringMapSize8  = 1024 + 2
	stringMapSize9  = 2048 + 2
	stringMapSize10 = 4096 + 2

	StringMapSize7a = 512
)

var (
	StringMapsSizes = [StringMapsNumSubMaps]int{
		stringMapSize0,
		stringMapSize1,
		stringMapSize2,
		stringMapSize3,
		stringMapSize4,
		stringMapSize5,
		stringMapSize6,
		stringMapSize7,
		stringMapSize8,
		stringMapSize9,
		stringMapSize10,
	}
)

type StringMapLists [StringMapsNumSubMaps][]map[[MaxStringMapsSize]byte]struct{}
type SelectorStringMaps [StringMapsNumSubMaps]map[[MaxStringMapsSize]byte]struct{}

type KernelLPMTrieStringPrefix struct {
	prefixLen uint32
	data      [StringPrefixMaxLength]byte
}

type KernelLPMTrieStringPostfix struct {
	prefixLen uint32
	data      [StringPostfixMaxLength]byte
}

type KernelSelectorMaps struct {
	// stringMaps are used to populate string and char buf matches
	stringMaps StringMapLists
	// stringPrefixMaps are used to populate string and char buf prefix matches
	stringPrefixMaps []map[KernelLPMTrieStringPrefix]struct{}
	// stringPostfixMaps are used to populate string and char buf postfix matches
	stringPostfixMaps []map[KernelLPMTrieStringPostfix]struct{}
}

type MatchBinariesSelectorOptions struct {
	Op    uint32
	MapID uint32
	// matchBinaries set for the selector
	MBSetID uint32
}

type KernelSelectorData struct {
	off uint32     // offset into encoding
	e   [4096]byte // kernel encoding of selectors
}

type KernelSelectorState struct {
	data KernelSelectorData

	// valueMaps are used to populate value maps for InMap and NotInMap operators
	valueMaps []ValueMap

	// addr4Maps are used to populate IPv4 address LpmTrie maps for sock and skb operators
	addr4Maps []map[KernelLPMTrie4]struct{}

	// addr6Maps are used to populate IPv6 address LpmTrie maps for sock and skb operators
	addr6Maps []map[KernelLPMTrie6]struct{}

	matchBinaries      map[int]MatchBinariesSelectorOptions
	matchBinariesPaths map[int][][processapi.BINARY_PATH_MAX_LEN]byte

	listReader ValueReader

	maps *KernelSelectorMaps
}

func NewKernelSelectorState(listReader ValueReader, maps *KernelSelectorMaps) *KernelSelectorState {
	if maps == nil {
		maps = &KernelSelectorMaps{}
	}
	return &KernelSelectorState{
		matchBinaries:      make(map[int]MatchBinariesSelectorOptions),
		matchBinariesPaths: make(map[int][][processapi.BINARY_PATH_MAX_LEN]byte),
		listReader:         listReader,
		maps:               maps,
	}
}

func (k KernelSelectorState) MatchBinaries() map[int]MatchBinariesSelectorOptions {
	return k.matchBinaries
}

func (k *KernelSelectorState) AddMatchBinaries(i int, sel MatchBinariesSelectorOptions) {
	k.matchBinaries[i] = sel
}

func (k KernelSelectorState) MatchBinariesPaths() map[int][][processapi.BINARY_PATH_MAX_LEN]byte {
	return k.matchBinariesPaths
}

func (k *KernelSelectorState) WriteMatchBinariesPath(selectorID int, path string) {
	var bytePath [processapi.BINARY_PATH_MAX_LEN]byte
	copy(bytePath[:], path)
	k.matchBinariesPaths[selectorID] = append(k.matchBinariesPaths[selectorID], bytePath)
}

// MatchBinariesPathsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) MatchBinariesPathsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.matchBinariesPaths {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

func (k *KernelSelectorState) Buffer() [4096]byte {
	return k.data.e
}

func (k *KernelSelectorState) ValueMaps() []ValueMap {
	return k.valueMaps
}

func (k *KernelSelectorState) Addr4Maps() []map[KernelLPMTrie4]struct{} {
	return k.addr4Maps
}

func (k *KernelSelectorState) Addr6Maps() []map[KernelLPMTrie6]struct{} {
	return k.addr6Maps
}

func (k *KernelSelectorState) StringMaps(subMap int) []map[[MaxStringMapsSize]byte]struct{} {
	return k.maps.stringMaps[subMap]
}

func (k *KernelSelectorState) StringPrefixMaps() []map[KernelLPMTrieStringPrefix]struct{} {
	return k.maps.stringPrefixMaps
}

func (k *KernelSelectorState) StringPostfixMaps() []map[KernelLPMTrieStringPostfix]struct{} {
	return k.maps.stringPostfixMaps
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

// StringMapsMaxEntries returns the maximum entries over all maps inside a particular map of map
func (k *KernelSelectorState) StringMapsMaxEntries(subMap int) int {
	maxEntries := 1
	for _, vm := range k.maps.stringMaps[subMap] {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

// StringPrefixMapsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) StringPrefixMapsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.maps.stringPrefixMaps {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

// StringPostfixMapsMaxEntries returns the maximum entries over all maps
func (k *KernelSelectorState) StringPostfixMapsMaxEntries() int {
	maxEntries := 1
	for _, vm := range k.maps.stringPostfixMaps {
		if l := len(vm); l > maxEntries {
			maxEntries = l
		}
	}
	return maxEntries
}

func WriteSelectorInt32(k *KernelSelectorData, v int32) {
	binary.LittleEndian.PutUint32(k.e[k.off:], uint32(v))
	k.off += 4
}

func WriteSelectorUint32(k *KernelSelectorData, v uint32) {
	binary.LittleEndian.PutUint32(k.e[k.off:], v)
	k.off += 4
}

func WriteSelectorInt64(k *KernelSelectorData, v int64) {
	binary.LittleEndian.PutUint64(k.e[k.off:], uint64(v))
	k.off += 8
}

func WriteSelectorUint64(k *KernelSelectorData, v uint64) {
	binary.LittleEndian.PutUint64(k.e[k.off:], v)
	k.off += 8
}

func WriteSelectorLength(k *KernelSelectorData, loff uint32) {
	diff := k.off - loff
	binary.LittleEndian.PutUint32(k.e[loff:], diff)
}

func WriteSelectorOffsetUint32(k *KernelSelectorData, loff uint32, val uint32) {
	binary.LittleEndian.PutUint32(k.e[loff:], val)
}

func GetCurrentOffset(k *KernelSelectorData) uint32 {
	return k.off
}

func WriteSelectorByteArray(k *KernelSelectorData, b []byte, size uint32) {
	for l := uint32(0); l < size; l++ {
		k.e[k.off+l] = b[l]
	}
	k.off += size
}

func AdvanceSelectorLength(k *KernelSelectorData) uint32 {
	off := k.off
	k.off += 4
	return off
}

func ArgSelectorValue(v string) ([]byte, uint32) {
	b := []byte(v)
	return b, uint32(len(b))
}

func stringPaddedLen(s int) int {
	paddedLen := s

	if s <= 6*stringMapsKeyIncSize {
		if s%stringMapsKeyIncSize != 0 {
			paddedLen = ((s / stringMapsKeyIncSize) + 1) * stringMapsKeyIncSize
		}
		return paddedLen
	}
	// The '-2' is to reduce the key size to the key string size -
	// the key includes a string length that is 2 bytes long.
	if s <= stringMapSize6-2 {
		return stringMapSize6 - 2
	}
	if kernels.MinKernelVersion("5.11") {
		if s <= stringMapSize7-2 {
			return stringMapSize7 - 2
		}
		if s <= stringMapSize8-2 {
			return stringMapSize8 - 2
		}
		if s <= stringMapSize9-2 {
			return stringMapSize9 - 2
		}
		return stringMapSize10 - 2
	}
	return StringMapSize7a - 2
}

func ArgStringSelectorValue(v string, removeNul bool) ([MaxStringMapsSize]byte, int, error) {
	if removeNul {
		// Remove any trailing nul characters ("\0" or 0x00)
		for v[len(v)-1] == 0 {
			v = v[0 : len(v)-1]
		}
	}
	ret := [MaxStringMapsSize]byte{}
	b := []byte(v)
	s := len(b)
	if kernels.MinKernelVersion("5.11") {
		if s > MaxStringMapsSize-2 {
			return ret, 0, fmt.Errorf("string is too long")
		}
	} else if kernels.MinKernelVersion("5.4") {
		if s > StringMapSize7a-2 {
			return ret, 0, fmt.Errorf("string is too long")
		}
	} else {
		if s > stringMapSize5-1 {
			return ret, 0, fmt.Errorf("string is too long")
		}
	}
	if s == 0 {
		return ret, 0, fmt.Errorf("string is empty")
	}
	// Calculate length of string padded to next multiple of key increment size
	paddedLen := stringPaddedLen(s)

	// Add real length to start and padding to end.
	// u8 for first 6 maps and u16 little endian for latter maps.
	if paddedLen <= 6*stringMapsKeyIncSize {
		ret[0] = byte(s)
		copy(ret[1:], b)
		// Total length is padded string len + prefixed length byte.
		return ret, paddedLen + 1, nil
	}
	ret[0] = byte(s % 0x100)
	ret[1] = byte(s / 0x100)
	copy(ret[2:], b)
	// Total length is padded string len + prefixed length half word.
	return ret, paddedLen + 2, nil
}

func ArgPostfixSelectorValue(v string, removeNul bool) ([]byte, uint32) {
	if removeNul {
		// Remove any trailing nul characters ("\0" or 0x00)
		for v[len(v)-1] == 0 {
			v = v[0 : len(v)-1]
		}
	}
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

func (k *KernelSelectorState) createAddr4Map() map[KernelLPMTrie4]struct{} {
	return map[KernelLPMTrie4]struct{}{}
}

func (k *KernelSelectorState) insertAddr4Map(addr4map map[KernelLPMTrie4]struct{}) uint32 {
	mapid := len(k.addr4Maps)
	k.addr4Maps = append(k.addr4Maps, addr4map)
	return uint32(mapid)
}

func (k *KernelSelectorState) createAddr6Map() map[KernelLPMTrie6]struct{} {
	return map[KernelLPMTrie6]struct{}{}
}

func (k *KernelSelectorState) insertAddr6Map(addr6map map[KernelLPMTrie6]struct{}) uint32 {
	mapid := len(k.addr6Maps)
	k.addr6Maps = append(k.addr6Maps, addr6map)
	return uint32(mapid)
}

func (k *KernelSelectorState) createStringMaps() SelectorStringMaps {
	return SelectorStringMaps{
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
		{},
	}
}

// In BPF, the string "equal" operator uses 11 hash maps, each stored within a matching array.
// For each kprobe there could be multiple string match selectors. Each of these selectors has
// up to 11 hash maps (of different sizes) that hold potential matches. Each kprobe could have
// multiple string match selectors (for different parameters, and/or different actions). Arrays
// of hash maps can only hold hash maps of a singular type; e.g. an array of hash maps with a
// key size of 25 can only hold hash maps that have that key size – it can't hold hash maps with
// different key sizes.
//
// As we have 11 different key sizes (to facilitate faster look ups for shorter strings), each
// selector can potentially have 11 hash maps to look up the string in. And as each kprobe
// could have multiple string match selectors, each kprobe could potentially have multiple hash
// maps for each key size. Each kprobe therefore has 11 arrays of hash maps to hold these hash
// maps.
//
// In golang we create a list of hash maps for each key size. Each of these is inserted into the
// corresponding array of hash maps in BPF. The indices of the arrays correspond to the positions
// in the list. As we don't needlessly create hash maps when they would otherwise be empty, we
// also don't insert empty hash maps into the array. Therefore, at look up, it is possible that
// there is no hash map for a particular key size for a particular selector. In this instance,
// instead of storing the index of the hash map, we store 0xffffffff (int32(-1)) to indicate that
// no hash map exists for that key size.
//
// For a simpler example of this construction, see the InMap functionality.
func (k *KernelSelectorState) insertStringMaps(stringMaps SelectorStringMaps) [StringMapsNumSubMaps]uint32 {

	details := [StringMapsNumSubMaps]uint32{}
	mapid := uint32(0)

	for subMap := 0; subMap < StringMapsNumSubMaps; subMap++ {
		if len(stringMaps[subMap]) > 0 {
			mapid = uint32(len(k.maps.stringMaps[subMap]))
			k.maps.stringMaps[subMap] = append(k.maps.stringMaps[subMap], stringMaps[subMap])
		} else {
			mapid = 0xffffffff
		}
		details[subMap] = mapid
	}

	return details
}

func (k *KernelSelectorState) newStringPrefixMap() (uint32, map[KernelLPMTrieStringPrefix]struct{}) {
	mapid := len(k.maps.stringPrefixMaps)
	k.maps.stringPrefixMaps = append(k.maps.stringPrefixMaps, map[KernelLPMTrieStringPrefix]struct{}{})
	return uint32(mapid), k.maps.stringPrefixMaps[mapid]
}

func (k *KernelSelectorState) newStringPostfixMap() (uint32, map[KernelLPMTrieStringPostfix]struct{}) {
	mapid := len(k.maps.stringPostfixMaps)
	k.maps.stringPostfixMaps = append(k.maps.stringPostfixMaps, map[KernelLPMTrieStringPostfix]struct{}{})
	return uint32(mapid), k.maps.stringPostfixMaps[mapid]
}

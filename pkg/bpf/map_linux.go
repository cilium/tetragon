// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package bpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"syscall"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/tetragon/pkg/lock"

	"golang.org/x/sys/unix"
)

type MapKey interface {
	fmt.Stringer

	// Returns pointer to start of key
	GetKeyPtr() unsafe.Pointer

	// Allocates a new value matching the key type
	NewValue() MapValue

	// DeepCopyMapKey returns a deep copy of the map key
	DeepCopyMapKey() MapKey
}

type MapValue interface {
	fmt.Stringer

	// Returns pointer to start of value
	GetValuePtr() unsafe.Pointer

	// DeepCopyMapValue returns a deep copy of the map value
	DeepCopyMapValue() MapValue
}

type MapInfo struct {
	MapType  MapType
	MapKey   MapKey
	KeySize  uint32
	MapValue MapValue
	// ReadValueSize is the value size that is used to read from the BPF maps
	// this value an the ValueSize values can be different for BPF_MAP_TYPE_PERCPU_HASH
	// for example.
	ReadValueSize uint32
	ValueSize     uint32
	MaxEntries    uint32
	Flags         uint32
	InnerID       uint32
}

type Map struct {
	MapInfo
	fd   int
	name string
	path string
	lock lock.RWMutex
}

func (m *Map) GetFd() int {
	return m.fd
}

// Name returns the basename of this map.
func (m *Map) Name() string {
	return m.name
}

// Path returns the path to this map on the filesystem.
func (m *Map) Path() string {
	return m.path
}

func GetMapInfo(pid int, fd int) (*MapInfo, error) {
	fdinfoFile := fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd)

	file, err := os.Open(fdinfoFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info := &MapInfo{}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var value int

		line := scanner.Text()
		if n, err := fmt.Sscanf(line, "map_type:\t%d", &value); n == 1 && err == nil {
			info.MapType = MapType(value)
		} else if n, err := fmt.Sscanf(line, "key_size:\t%d", &value); n == 1 && err == nil {
			info.KeySize = uint32(value)
		} else if n, err := fmt.Sscanf(line, "value_size:\t%d", &value); n == 1 && err == nil {
			info.ValueSize = uint32(value)
			info.ReadValueSize = uint32(value)
		} else if n, err := fmt.Sscanf(line, "max_entries:\t%d", &value); n == 1 && err == nil {
			info.MaxEntries = uint32(value)
		} else if n, err := fmt.Sscanf(line, "map_flags:\t0x%x", &value); n == 1 && err == nil {
			info.Flags = uint32(value)
		}
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return info, nil
}

// OpenMap opens the given bpf map and generates the Map info based in the
// information stored in the bpf map.
// *Warning*: Calling this function requires the caller to properly setup
// the MapInfo.MapKey and MapInfo.MapValues fields as those structures are not
// stored in the bpf map.
func OpenMap(name string) (*Map, error) {
	fd, err := ObjGet(name)
	if err != nil {
		return nil, err
	}

	info, err := GetMapInfo(os.Getpid(), fd)
	if err != nil {
		return nil, err
	}

	if info.MapType == 0 {
		return nil, fmt.Errorf("Unable to determine map type")
	}

	if info.KeySize == 0 {
		return nil, fmt.Errorf("Unable to determine map key size")
	}

	m := &Map{
		MapInfo: *info,
		fd:      fd,
		name:    path.Base(name),
		path:    name,
	}

	return m, nil
}

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	pathStr, err := syscall.BytePtrFromString(pathname)
	if err != nil {
		return 0, err
	}
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
	}

	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || errno != 0 {
		return 0, &os.PathError{
			Op:   "Unable to get object",
			Err:  errno,
			Path: pathname,
		}
	}

	return int(fd), nil
}

func (m *Map) Open() error {
	if m.fd != 0 {
		return nil
	}

	fd, err := ObjGet(m.path)
	if err != nil {
		return err
	}

	m.fd = fd
	return nil
}

func (m *Map) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.fd != 0 {
		unix.Close(m.fd)
		m.fd = 0
	}

	return nil
}

// Reopen attempts to close and re-open the received map.
func (m *Map) Reopen() error {
	m.Close()
	return m.Open()
}

type DumpCallback func(m *Map, key MapKey, value MapValue)
type MapValidator func(path string) (bool, error)

// ConvertKeyValue converts key and value from bytes to given Golang struct pointers.
func ConvertKeyValue(bKey []byte, bValue []byte, key MapKey, value MapValue) (MapKey, MapValue, error) {

	if len(bKey) > 0 {
		if err := binary.Read(bytes.NewReader(bKey), byteorder.Native, key); err != nil {
			return nil, nil, fmt.Errorf("Unable to convert key: %w", err)
		}
	}

	if len(bValue) > 0 {
		if err := binary.Read(bytes.NewReader(bValue), byteorder.Native, value); err != nil {
			return nil, nil, fmt.Errorf("Unable to convert value: %w", err)
		}
	}

	return key, value, nil
}

// Count returns the number of elements in the map by iterating
// over it with BPF_MAP_GET_NEXT_KEY.
func (m *Map) Count() (int, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)

	if err := m.Open(); err != nil {
		return 0, err
	}

	if err := GetFirstKey(m.fd, unsafe.Pointer(&nextKey[0])); err != nil {
		return 0, nil
	}

	bpfCurrentKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
		value: uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
	}
	bpfCurrentKeyPtr := uintptr(unsafe.Pointer(&bpfCurrentKey))
	bpfCurrentKeySize := unsafe.Sizeof(bpfCurrentKey)

	count := 1
	for {
		copy(key, nextKey)
		if err := GetNextKeyFromPointers(m.fd, bpfCurrentKeyPtr, bpfCurrentKeySize); err != nil {
			break
		}
		count++
	}
	return count, nil

}

// DumpWithCallback iterates over the Map and calls the given callback
// function on each iteration. That callback function is receiving the
// actual key and value. The callback function should consider creating a
// deepcopy of the key and value on between each iterations to avoid memory
// corruption.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
	m.lock.RLock()
	defer m.lock.RUnlock()

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)
	value := make([]byte, m.ReadValueSize)

	if err := m.Open(); err != nil {
		return err
	}

	if err := GetFirstKey(m.fd, unsafe.Pointer(&nextKey[0])); err != nil {
		return nil
	}

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	bpfCurrentKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
		value: uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
	}
	bpfCurrentKeyPtr := uintptr(unsafe.Pointer(&bpfCurrentKey))
	bpfCurrentKeySize := unsafe.Sizeof(bpfCurrentKey)

	bpfNextKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
		value: uint64(uintptr(unsafe.Pointer(&value[0]))),
	}

	bpfNextKeyPtr := uintptr(unsafe.Pointer(&bpfNextKey))
	bpfNextKeySize := unsafe.Sizeof(bpfNextKey)

	for {
		err := LookupElementFromPointers(m.fd, bpfNextKeyPtr, bpfNextKeySize)
		if err != nil {
			return err
		}

		mk, mv, err = ConvertKeyValue(nextKey, value, mk, mv)
		if err != nil {
			return err
		}

		if cb != nil {
			cb(m, mk, mv)
		}

		copy(key, nextKey)

		err = GetNextKeyFromPointers(m.fd, bpfCurrentKeyPtr, bpfCurrentKeySize)
		if err != nil {
			break
		}
	}
	return nil
}

// DumpWithCallbackIfExists is similar to DumpWithCallback, but returns earlier
// if the given map does not exist.
func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.DumpWithCallback(cb)
	}

	return nil
}

// Dump returns the map (type map[string][]string) which contains all
// data stored in BPF map.
func (m *Map) Dump(hash map[string][]string) error {
	callback := func(m *Map, key MapKey, value MapValue) {
		// No need to deep copy since we are creating strings.
		hash[key.String()] = append(hash[key.String()], value.String())
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := m.DumpWithCallback(callback); err != nil {
		return err
	}

	return nil
}

// DumpIfExists dumps the contents of the map into hash via Dump() if the map
// file exists
func (m *Map) DumpIfExists(hash map[string][]string) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.Dump(hash)
	}

	return nil
}

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	value := key.NewValue()

	if err := m.Open(); err != nil {
		return nil, err
	}

	err := LookupElement(m.fd, key.GetKeyPtr(), value.GetValuePtr())
	if err != nil {
		return nil, err
	}
	return value, nil
}

func UpdateElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: uint64(flags),
	}

	return UpdateElementFromPointers(fd, uintptr(unsafe.Pointer(&uba)), unsafe.Sizeof(uba))
}

func (m *Map) Update(key MapKey, value MapValue) error {
	var err error

	m.lock.Lock()
	defer m.lock.Unlock()

	if err = m.Open(); err != nil {
		return err
	}

	return UpdateElement(m.fd, key.GetKeyPtr(), value.GetValuePtr(), 0)
}

// GetNextKeyFromPointers stores, in nextKey, the next key after the key of the map in fd.
func GetNextKeyFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_KEY,
		structPtr,
		sizeOfStruct,
	)
	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to get next key from map with file descriptor %d: %s", fd, err)
	}
	return nil
}

// GetNextKey stores, in nextKey, the next key after the key of the map in fd.
// Deprecated, use GetNextKeyFromPointers
func GetNextKey(fd int, key, nextKey unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(nextKey)),
	}

	return GetNextKeyFromPointers(fd, uintptr(unsafe.Pointer(&uba)), unsafe.Sizeof(uba))
}

// GetFirstKey fetches the first key in the map.
func GetFirstKey(fd int, nextKey unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   0, // NULL -> Get first element
		value: uint64(uintptr(nextKey)),
	}

	return GetNextKeyFromPointers(fd, uintptr(unsafe.Pointer(&uba)), unsafe.Sizeof(uba))
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElementFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		structPtr,
		sizeOfStruct,
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element in map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
// Deprecated, use LookupElementFromPointers
func LookupElement(fd int, key, value unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}

	return LookupElementFromPointers(fd, uintptr(unsafe.Pointer(&uba)), unsafe.Sizeof(uba))
}

func (m *Map) exist() (bool, error) {
	path := m.Path()
	if _, err := os.Stat(path); err == nil {
		return true, nil
	}

	return false, nil
}

func deleteElement(fd int, key unsafe.Pointer) (uintptr, unix.Errno) {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	return ret, err
}

// deleteMapEntry deletes the map entry corresponding to the given key.
// If ignoreMissing is set to true and the entry is not found, then
// the error metric is not incremented for missing entries and nil error is returned.
func (m *Map) DeleteKey(key MapKey) error {
	_, errno := deleteElement(m.fd, key.GetKeyPtr())

	// Error handling is skipped in the case ignoreMissing is set and the
	// error is ENOENT. This removes false positives in the delete metrics
	// and skips the deferred cleanup of non-existing entries. This situation
	// occurs at least in the context of cleanup of NAT mappings from CT GC.
	handleError := errno != unix.ENOENT
	if errno != 0 && handleError {
		return fmt.Errorf("unable to delete element %s from map %s: %d", key, m.name, errno)
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package byteorder provides helpers for tests to compute values in network byte order without
// assuming the byte order of the host.
package byteorder

import "encoding/binary"

// HostToNetwork16 converts a 16-bit value from host to network (big-endian) byte order.
func HostToNetwork16(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

// HostToNetwork32 converts a 32-bit value from host to network (big-endian) byte order.
func HostToNetwork32(v uint32) uint32 {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return binary.BigEndian.Uint32(b[:])
}

// HostToNetwork64 converts a 64-bit value from host to network (big-endian) byte order.
func HostToNetwork64(v uint64) uint64 {
	var b [8]byte
	binary.NativeEndian.PutUint64(b[:], v)
	return binary.BigEndian.Uint64(b[:])
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package network

import (
	"encoding/binary"
	"net/netip"

	"github.com/cilium/tetragon/pkg/constants"
)

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

func GetIPv4(i uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], i)
	return netip.AddrFrom4(b)
}

func GetIP(i [2]uint64, family uint16) netip.Addr {
	switch family {
	case constants.AF_INET:
		return GetIPv4(uint32(i[0]))
	case constants.AF_INET6:
		var b [16]byte
		binary.LittleEndian.PutUint64(b[:8], i[0])
		binary.LittleEndian.PutUint64(b[8:], i[1])
		return netip.AddrFrom16(b)
	}
	return netip.Addr{}
}

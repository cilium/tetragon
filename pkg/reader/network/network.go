// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package network

import (
	"encoding/binary"
	"net"

	"github.com/cilium/tetragon/pkg/constants"
)

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

func GetIPv4(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func GetIP(i [2]uint64, family uint16) net.IP {
	switch family {
	case constants.AF_INET:
		return GetIPv4(uint32(i[0]))
	case constants.AF_INET6:
		a := make([]byte, 8)
		b := make([]byte, 8)

		binary.LittleEndian.PutUint64(a, i[0])
		binary.LittleEndian.PutUint64(b, i[1])
		// nolint:makezero // slices carefully manipulated like arrays
		ip := append(a, b...)
		return ip
	}
	return nil
}

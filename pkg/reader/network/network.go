// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package network

import (
	"encoding/binary"
	"net"
)

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

func GetIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

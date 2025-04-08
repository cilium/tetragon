// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// helper functions to manage 5-tuples
package vtuple

import (
	"fmt"
	"net"
)

type VTuple interface {
	IsUDP() bool
	IsTCP() bool
	IsIP4() bool
	IsIP6() bool

	SrcAddr() net.IP
	DstAddr() net.IP
	SrcPort() uint16
	DstPort() uint16
}

const (
	VT_IP4     = 0x4000
	VT_IP6     = 0x6000
	VT_L3_MASK = 0xff00

	// Let's use the actual TCP/UDP nextheader ids because why not?
	VT_TCP     = 0x06
	VT_UDP     = 0x11
	VT_L4_MASK = 0xff

	VT_TCP4 = VT_IP4 | VT_TCP
	VT_TCP6 = VT_IP6 | VT_TCP
	VT_UDP4 = VT_IP4 | VT_UDP
	VT_UDP6 = VT_IP6 | VT_UDP
)

type Impl struct {
	srcAddr net.IP
	dstAddr net.IP
	srcPort uint16
	dstPort uint16
	proto   uint16
}

func (t *Impl) IsUDP() bool {
	return (t.proto & VT_L4_MASK) == VT_UDP
}

func (t *Impl) IsTCP() bool {
	return (t.proto & VT_L4_MASK) == VT_TCP
}
func (t *Impl) IsIP4() bool {
	return (t.proto & VT_L3_MASK) == VT_IP4
}
func (t *Impl) IsIP6() bool {
	return (t.proto & VT_L3_MASK) == VT_IP6
}
func (t *Impl) SrcAddr() net.IP {
	return t.srcAddr[:]
}
func (t *Impl) DstAddr() net.IP {
	return t.dstAddr[:]
}
func (t *Impl) SrcPort() uint16 {
	return t.srcPort
}
func (t *Impl) DstPort() uint16 {
	return t.dstPort
}

func CreateTCPv4(saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) Impl {
	return Impl{
		proto:   VT_TCP4,
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}

}

func CreateUDPv4(saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) Impl {
	return Impl{
		proto:   VT_UDP4,
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}

}

type UnknownV4ProtocolError struct {
	proto byte
}

func (e *UnknownV4ProtocolError) Error() string {
	return fmt.Sprintf("unsupported protocol: %d", e.proto)
}

func CreateVTupleV4(proto byte, saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) (Impl, error) {

	switch proto {
	case VT_TCP, VT_UDP:
	default:
		return Impl{}, &UnknownV4ProtocolError{proto: proto}
	}

	return Impl{
		proto:   VT_IP4 | uint16(proto),
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}, nil
}

func StringRep(vt VTuple) string {
	proto := "?"
	if vt.IsTCP() {
		proto = "tcp"
	} else if vt.IsUDP() {
		proto = "udp"
	}

	return fmt.Sprintf("%s:%d→%s:%d/%s", vt.SrcAddr(), vt.SrcPort(), vt.DstAddr(), vt.DstPort(), proto)
}

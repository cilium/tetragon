// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package network

import (
	"fmt"
)

func InetFamily(family uint16) string {

	if f, ok := inetFamily[family]; ok {
		return f
	}
	return fmt.Sprintf("%d", family)
}

func InetFamilyNumber(family string) (uint16, error) {
	for familynum, familystr := range inetFamily {
		if family == familystr {
			return familynum, nil
		}
	}
	return 0, fmt.Errorf("address family string not known")
}

var inetType = map[uint16]string{
	1: "SOCK_STREAM",
	2: "SOCK_DGRAM",
	3: "SOCK_RAW",
	4: "SOCK_RDM",
	5: "SOCK_SEQPACKET",
	6: "SOCK_DCCP",
	7: "SOCK_PACKET",
}

func InetType(ty uint16) string {
	if t, ok := inetType[ty]; ok {
		return t
	}
	return fmt.Sprintf("%d", ty)
}

var inetProtocol = map[uint16]string{
	0:   "IPPROTO_IP",
	1:   "IPPROTO_ICMP",
	2:   "IPPROTO_IGMP",
	4:   "IPPROTO_IPIP",
	6:   "IPPROTO_TCP",
	8:   "IPPROTO_EGP",      /* Exterior Gateway Protocol            */
	12:  "IPPROTO_PUP",      /* PUP protocol                         */
	17:  "IPPROTO_UDP",      /* User Datagram Protocol               */
	22:  "IPPROTO_IDP",      /* XNS IDP protocol                     */
	29:  "IPPROTO_TP",       /* SO Transport Protocol Class 4        */
	33:  "IPPROTO_DCCP",     /* Datagram Congestion Control Protocol */
	41:  "IPPROTO_IPV6",     /* IPv6-in-IPv4 tunnelling              */
	46:  "IPPROTO_RSVP",     /* RSVP Protocol                        */
	47:  "IPPROTO_GRE",      /* Cisco GRE tunnels (rfc 1701,1702)    */
	50:  "IPPROTO_ESP",      /* Encapsulation Security Payload protocol */
	51:  "IPPROTO_AH",       /* Authentication Header protocol       */
	92:  "IPPROTO_MTP",      /* Multicast Transport Protocol         */
	94:  "IPPROTO_BEETPH",   /* IP option pseudo header for BEET     */
	98:  "IPPROTO_ENCAP",    /* Encapsulation Header                 */
	103: "IPPROTO_PIM",      /* Protocol Independent Multicast       */
	108: "IPPROTO_COMP",     /* Compression Header Protocol          */
	132: "IPPROTO_SCTP",     /* Stream Control Transport Protocol    */
	136: "IPPROTO_UDPLITE",  /* UDP-Lite (RFC 3828)                  */
	137: "IPPROTO_MPLS",     /* MPLS in IP (RFC 4023)                */
	143: "IPPROTO_ETHERNET", /* Ethernet-within-IPv6 Encapsulation   */
	255: "IPPROTO_RAW",      /* Raw IP packets                       */
	262: "IPPROTO_MPTCP",    /* Multipath TCP connection             */
}

func InetProtocol(proto uint16) string {
	if p, ok := inetProtocol[proto]; ok {
		return p
	}
	return fmt.Sprintf("%d", proto)
}

func InetProtocolNumber(proto string) (uint16, error) {
	for protonum, protostr := range inetProtocol {
		if proto == protostr {
			return protonum, nil
		}
	}
	return 0, fmt.Errorf("protocol string not known")
}

var tcpState = map[uint8]string{
	1:  "TCP_ESTABLISHED",
	2:  "TCP_SYN_SENT",
	3:  "TCP_SYN_RECV",
	4:  "TCP_FIN_WAIT1",
	5:  "TCP_FIN_WAIT2",
	6:  "TCP_TIME_WAIT",
	7:  "TCP_CLOSE",
	8:  "TCP_CLOSE_WAIT",
	9:  "TCP_LAST_ACK",
	10: "TCP_LISTEN",
	11: "TCP_CLOSING",
	12: "TCP_NEW_SYN_RECV",
}

func TcpState(state uint8) string {
	if p, ok := tcpState[state]; ok {
		return p
	}
	return fmt.Sprintf("%d", state)
}

func TcpStateNumber(state string) (uint8, error) {
	for statenum, statestr := range tcpState {
		if state == statestr {
			return statenum, nil
		}
	}
	return 0, fmt.Errorf("state string not known")
}

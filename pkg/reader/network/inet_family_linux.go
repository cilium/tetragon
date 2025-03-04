// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package network

import (
	"github.com/cilium/tetragon/pkg/constants"
)

var inetFamily = map[uint16]string{
	constants.AF_UNSPEC:     "AF_UNSPEC",
	constants.AF_UNIX:       "AF_UNIX",
	constants.AF_INET:       "AF_INET",
	constants.AF_AX25:       "AF_AX25",
	constants.AF_IPX:        "AF_IPX",
	constants.AF_APPLETALK:  "AF_APPLETALK",
	constants.AF_NETROM:     "AF_NETROM",
	constants.AF_BRIDGE:     "AF_BRIDGE",
	constants.AF_ATMPVC:     "AF_ATMPVC",
	constants.AF_X25:        "AF_X25",
	constants.AF_INET6:      "AF_INET6",
	constants.AF_ROSE:       "AF_ROSE",
	constants.AF_DECnet:     "AF_DECnet",
	constants.AF_NETBEUI:    "AF_NETBEUI",
	constants.AF_SECURITY:   "AF_SECURITY",
	constants.AF_KEY:        "AF_KEY",
	constants.AF_NETLINK:    "AF_NETLINK",
	constants.AF_PACKET:     "AF_PACKET",
	constants.AF_ASH:        "AF_ASH",
	constants.AF_ECONET:     "AF_ECONET",
	constants.AF_ATMSVC:     "AF_ATMSVC",
	constants.AF_RDS:        "AF_RDS",
	constants.AF_IRDA:       "AF_IRDA",
	constants.AF_PPPOX:      "AF_PPPOX",
	constants.AF_WANPIPE:    "AF_WANPIPE",
	constants.AF_LLC:        "AF_LLC",
	constants.AF_IB:         "AF_IB",
	constants.AF_MPLS:       "AF_MPLS",
	constants.AF_CAN:        "AF_CAN",
	constants.AF_TIPC:       "AF_TIPC",
	constants.AF_BLUETOOTH:  "AF_BLUETOOTH",
	constants.AF_IUCV:       "AF_IUCV",
	constants.AF_RXRPC:      "AF_RXRPC",
	constants.AF_ISDN:       "AF_ISDN",
	constants.AF_PHONET:     "AF_PHONET",
	constants.AF_IEEE802154: "AF_IEEE802154",
	constants.AF_CAIF:       "AF_CAIF",
	constants.AF_ALG:        "AF_ALG",
	constants.AF_NFC:        "AF_NFC",
	constants.AF_VSOCK:      "AF_VSOCK",
	constants.AF_KCM:        "AF_KCM",
	constants.AF_QIPCRTR:    "AF_QIPCRTR",
	constants.AF_SMC:        "AF_SMC",
	constants.AF_XDP:        "AF_XDP",
	constants.AF_MCTP:       "AF_MCTP",
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package constants

import (
	"golang.org/x/sys/unix"
)

const (
	PERF_MAX_STACK_DEPTH = unix.PERF_MAX_STACK_DEPTH
	CBitFieldMaskBit34   = unix.CBitFieldMaskBit34
	CGROUP2_SUPER_MAGIC  = unix.CGROUP2_SUPER_MAGIC
	CAP_LAST_CAP         = unix.CAP_LAST_CAP
	CAP_CHOWN            = unix.CAP_CHOWN
	AF_UNSPEC            = unix.AF_UNSPEC
	AF_UNIX              = unix.AF_UNIX
	AF_INET              = unix.AF_INET
	AF_AX25              = unix.AF_AX25
	AF_IPX               = unix.AF_IPX
	AF_APPLETALK         = unix.AF_APPLETALK
	AF_NETROM            = unix.AF_NETROM
	AF_BRIDGE            = unix.AF_BRIDGE
	AF_ATMPVC            = unix.AF_ATMPVC
	AF_X25               = unix.AF_X25
	AF_INET6             = unix.AF_INET6
	AF_ROSE              = unix.AF_ROSE
	AF_DECnet            = unix.AF_DECnet
	AF_NETBEUI           = unix.AF_NETBEUI
	AF_SECURITY          = unix.AF_SECURITY
	AF_KEY               = unix.AF_KEY
	AF_NETLINK           = unix.AF_NETLINK
	AF_PACKET            = unix.AF_PACKET
	AF_ASH               = unix.AF_ASH
	AF_ECONET            = unix.AF_ECONET
	AF_ATMSVC            = unix.AF_ATMSVC
	AF_RDS               = unix.AF_RDS
	AF_IRDA              = unix.AF_IRDA
	AF_PPPOX             = unix.AF_PPPOX
	AF_WANPIPE           = unix.AF_WANPIPE
	AF_LLC               = unix.AF_LLC
	AF_IB                = unix.AF_IB
	AF_MPLS              = unix.AF_MPLS
	AF_CAN               = unix.AF_CAN
	AF_TIPC              = unix.AF_TIPC
	AF_BLUETOOTH         = unix.AF_BLUETOOTH
	AF_IUCV              = unix.AF_IUCV
	AF_RXRPC             = unix.AF_RXRPC
	AF_ISDN              = unix.AF_ISDN
	AF_PHONET            = unix.AF_PHONET
	AF_IEEE802154        = unix.AF_IEEE802154
	AF_CAIF              = unix.AF_CAIF
	AF_ALG               = unix.AF_ALG
	AF_NFC               = unix.AF_NFC
	AF_VSOCK             = unix.AF_VSOCK
	AF_KCM               = unix.AF_KCM
	AF_QIPCRTR           = unix.AF_QIPCRTR
	AF_SMC               = unix.AF_SMC
	AF_XDP               = unix.AF_XDP
	AF_MCTP              = unix.AF_MCTP
)

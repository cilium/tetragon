// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package network

import (
	"github.com/cilium/tetragon/pkg/constants"
)

var inetFamily = map[uint16]string{
	0:                    "AF_UNSPEC",
	constants.AF_UNIX:    "AF_UNIX",
	constants.AF_INET:    "AF_INET",
	constants.AF_INET6:   "AF_INET6",
	constants.AF_IRDA:    "AF_IRDA",
	constants.AF_NETBIOS: "AF_NETBIOS",
	constants.AF_BTH:     "AF_BTH",
}

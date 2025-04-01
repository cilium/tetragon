// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"encoding/base64"
	"fmt"

	"github.com/cilium/tetragon/pkg/reader/node"
)

func GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", node.GetNodeNameForExport(), ktime, pid)))
}

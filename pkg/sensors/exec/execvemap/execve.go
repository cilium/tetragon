// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package execvemap

import (
	"github.com/cilium/tetragon/pkg/api/processapi"
)

type ExecveKey struct {
	Pid uint32
}

type ExecveValue struct {
	Process      processapi.MsgExecveKey    `align:"key"`
	Parent       processapi.MsgExecveKey    `align:"pkey"`
	Flags        uint32                     `align:"flags"`
	Nspid        uint32                     `align:"nspid"`
	CgrpId       uint64                     `align:"cgrpid"`
	Namespaces   processapi.MsgNamespaces   `align:"ns"`
	Capabilities processapi.MsgCapabilities `align:"caps"`
	Binary       processapi.Binary          `align:"bin"`
}

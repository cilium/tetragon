// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package execvemap

import (
	"fmt"
	"unsafe"

	"github.com/isovalent/tetragon-oss/pkg/api/processapi"
	"github.com/isovalent/tetragon-oss/pkg/bpf"
)

type ExecveKey struct {
	Pid uint32
}

type ExecveValueL struct {
	Common       processapi.MsgCommon
	Kube         processapi.MsgK8s
	Parent       processapi.MsgExecveKey
	ParentFlags  uint64
	Capabilities processapi.MsgCapabilities
}

type ExecveValue struct {
	Process processapi.MsgExecveKey
	Parent  processapi.MsgExecveKey
	Flags   uint32
	Nspid   uint32
	Buffer  uint64
}

func (k *ExecveKey) String() string             { return fmt.Sprintf("key=%d", k.Pid) }
func (k *ExecveKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *ExecveKey) DeepCopyMapKey() bpf.MapKey { return &ExecveKey{k.Pid} }

func (k *ExecveKey) NewValue() bpf.MapValue { return &ExecveValue{} }

func (v *ExecveValue) String() string {
	return fmt.Sprintf("value=%d %s", 0, "")
}
func (v *ExecveValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *ExecveValue) DeepCopyMapValue() bpf.MapValue {
	return &ExecveValue{}
}

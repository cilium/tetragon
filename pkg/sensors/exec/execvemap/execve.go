// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package execvemap

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/base"
)

type ExecveKey struct {
	Pid uint32
}

type ExecveValue struct {
	Process       processapi.MsgExecveKey    `align:"key"`
	Parent        processapi.MsgExecveKey    `align:"pkey"`
	Flags         uint32                     `align:"flags"`
	Nspid         uint32                     `align:"nspid"`
	Binary        uint32                     `align:"binary"`
	Pad           uint32                     `align:"pad"`
	CgrpIdTracker uint64                     `align:"cgrpid_tracker"`
	Namespaces    processapi.MsgNamespaces   `align:"ns"`
	Capabilities  processapi.MsgCapabilities `align:"caps"`
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

func LookupExecveMapStats() (int64, error) {
	execveMapStats := base.GetExecveMapStats()
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), execveMapStats.Name), nil)
	if err != nil {
		return -1, err
	}

	defer m.Close()

	var sum int64
	var v []int64
	err = m.Lookup(uint32(0), &v)
	if err != nil {
		return -1, err
	}

	for _, val := range v {
		sum += val
	}
	return sum, nil
}

package exec

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/base"
)

const (
	maxMapRetries = 4
	mapRetryDelay = 1
)

type ExecveAllowPolicyKey struct {
	Cookie [64]byte
}

type ExecveAllowPolicyValue struct {
	Parent [64]byte
}

func (k *ExecveAllowPolicyKey) String() string {
	return fmt.Sprintf("%d", k.Cookie)
}
func (k *ExecveAllowPolicyKey) NewValue() bpf.MapValue    { return &ExecveAllowPolicyValue{} }
func (k *ExecveAllowPolicyKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *ExecveAllowPolicyKey) DeepCopyMapKey() bpf.MapKey {
	return &ExecveAllowPolicyKey{Cookie: k.Cookie}
}

func (v *ExecveAllowPolicyValue) String() string {
	return fmt.Sprintf("%d", v.Parent)
}
func (v *ExecveAllowPolicyValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *ExecveAllowPolicyValue) DeepCopyMapValue() bpf.MapValue {
	return &ExecveAllowPolicyValue{Parent: v.Parent}
}

func writeAllowPolicy(ns, id, parent string) {
	mapDir := bpf.MapPrefixPath()
	m, err := bpf.OpenMap(filepath.Join(mapDir, base.ExecAllowMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, base.ExecAllowMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}

	defer m.Close()

	key := &ExecveAllowPolicyKey{}
	value := &ExecveAllowPolicyValue{}

	if id != "" {
		cookie, _ := hex.DecodeString(id)
		copy(key.Cookie[:32], cookie[:32])
	}

	if parent != "" {
		cookie, _ := hex.DecodeString(parent)
		copy(value.Parent[:32], cookie[:32])
	}

	err = m.Update(key, value)
}

package exec

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/base"
)

type ExecveCgroupKey struct {
	Id [128]byte
}

type ExecveCgroupValue struct {
	Enable uint32
}

func (k *ExecveCgroupKey) String() string {
	return fmt.Sprintf("%s", string(k.Id[:]))
}
func (k *ExecveCgroupKey) NewValue() bpf.MapValue    { return &ExecveCgroupValue{} }
func (k *ExecveCgroupKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *ExecveCgroupKey) DeepCopyMapKey() bpf.MapKey {
	return &ExecveCgroupKey{Id: k.Id}
}

func (v *ExecveCgroupValue) String() string {
	return fmt.Sprintf("%d", v.Enable)
}
func (v *ExecveCgroupValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *ExecveCgroupValue) DeepCopyMapValue() bpf.MapValue {
	return &ExecveCgroupValue{Enable: v.Enable}
}

func enableNs(dockerId [128]byte, enable uint32) {
	mapDir := bpf.MapPrefixPath()
	m, err := bpf.OpenMap(filepath.Join(mapDir, base.CgroupEnabledMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, base.CgroupEnabledMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}

	defer m.Close()

	key := &ExecveCgroupKey{
		Id: dockerId,
	}
	value := &ExecveCgroupValue{
		Enable: enable,
	}
	err = m.Update(key, value)
}

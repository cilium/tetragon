// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouptrackmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
)

type CgrpTrackingKey struct {
	CgrpId uint64
}

type CgrpTrackingValue struct {
	/* State of cgroup */
	State uint32

	/* Unique id for the hierarchy this is mostly for cgroupv1 */
	HierarchyId uint32

	/* The depth this cgroup is at - We don't track ancestors as they may change */
	Level uint32

	Pad uint32

	/* Cgroup kernfs_node name */
	Name [256]byte
}

func (k *CgrpTrackingKey) String() string             { return fmt.Sprintf("key=%d", k.CgrpId) }
func (k *CgrpTrackingKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *CgrpTrackingKey) DeepCopyMapKey() bpf.MapKey { return &CgrpTrackingKey{k.CgrpId} }

func (k *CgrpTrackingKey) NewValue() bpf.MapValue { return &CgrpTrackingValue{} }

func (v *CgrpTrackingValue) String() string {
	return fmt.Sprintf("value=%d %s", 0, "")
}
func (v *CgrpTrackingValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *CgrpTrackingValue) DeepCopyMapValue() bpf.MapValue {
	val := &CgrpTrackingValue{}
	val.State = v.State
	val.HierarchyId = v.HierarchyId
	val.Level = v.Level
	copy(val.Name[:256], v.Name[:256])
	return val
}

func LookupCgroupTracker(mapPath string, cgrpid uint64) (*CgrpTrackingValue, error) {
	logger.GetLogger().Debugf("Looking CgroupIdTracking=%d in '%q' map", cgrpid, mapPath)

	m, err := bpf.OpenMap(mapPath)
	if err != nil {
		return nil, err
	}

	defer m.Close()

	k := &CgrpTrackingKey{CgrpId: cgrpid}
	v, err := m.Lookup(k)
	if err != nil {
		return nil, err
	}

	val := v.DeepCopyMapValue().(*CgrpTrackingValue)

	return val, nil
}

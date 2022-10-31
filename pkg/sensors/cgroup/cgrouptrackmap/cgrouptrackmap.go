// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouptrackmap

import (
	"fmt"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
)

type CgrpTrackingKey struct {
	CgrpId uint64
}

type CgrpTrackingValue struct {
	/* State of cgroup */
	State int32 `align:"state"`

	/* Unique id for the hierarchy this is mostly for cgroupv1 */
	HierarchyId uint32 `align:"hierarchy_id"`

	/* The depth this cgroup is at - We don't track ancestors as they may change */
	Level uint32 `align:"level"`

	Pad uint32 `align:"pad"`

	/* Cgroup kernfs_node name */
	Name [processapi.CGROUP_NAME_LENGTH]byte `align:"name"`
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
	copy(val.Name[:processapi.CGROUP_NAME_LENGTH], v.Name[:processapi.CGROUP_NAME_LENGTH])
	return val
}

func LookupTrackingCgroup(mapPath string, cgrpid uint64) (*CgrpTrackingValue, error) {
	if cgrpid == 0 {
		return nil, fmt.Errorf("invalid CgroupIdTracking")
	}

	m, err := bpf.OpenMap(mapPath)
	if err != nil {
		return nil, err
	}

	defer m.Close()

	logger.GetLogger().WithFields(logrus.Fields{
		"cgroup.id": cgrpid,
		"bpf-map":   m.Name(),
	}).Trace("Looking for tracking CgroupID inside map")

	k := &CgrpTrackingKey{CgrpId: cgrpid}
	v, err := m.Lookup(k)
	if err != nil {
		return nil, err
	}

	val := v.DeepCopyMapValue().(*CgrpTrackingValue)

	return val, nil
}

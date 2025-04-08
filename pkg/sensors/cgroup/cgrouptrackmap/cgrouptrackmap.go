// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouptrackmap

import (
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
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

func LookupTrackingCgroup(mapPath string, cgrpid uint64) (*CgrpTrackingValue, error) {
	if cgrpid == 0 {
		return nil, errors.New("invalid CgroupIdTracking")
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, err
	}

	defer m.Close()

	logger.GetLogger().WithFields(logrus.Fields{
		"cgroup.id": cgrpid,
		"bpf-map":   mapPath,
	}).Trace("Looking for tracking CgroupID inside map")

	var v CgrpTrackingValue

	err = m.Lookup(&CgrpTrackingKey{CgrpId: cgrpid}, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouptrackmap

import (
	"testing"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/stretchr/testify/assert"
)

func TestDeepCopyMapValue(t *testing.T) {
	containerId := "docker-6917e69ec552a5b9ff0cd937586d8b7e8d9d77013a12571fa57a53fe681f5c07.scope"
	k := &CgrpTrackingValue{
		State:       int32(ops.CGROUP_RUNNING),
		HierarchyId: 4,
		Level:       5,
	}
	copy(k.Name[:processapi.CGROUP_NAME_LENGTH], containerId)

	val := k.DeepCopyMapValue().(*CgrpTrackingValue)
	assert.EqualValues(t, val, k)
	assert.Equal(t, containerId, cgroups.CgroupNameFromCStr(val.Name[:processapi.CGROUP_NAME_LENGTH]))
}

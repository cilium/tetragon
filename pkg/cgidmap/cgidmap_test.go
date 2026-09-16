// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCGIDMapContainersAndSandboxes(t *testing.T) {
	m, err := newMap()
	require.NoError(t, err)

	podID1 := uuid.New()
	podID2 := uuid.New()

	cont1 := "cont-1"
	cont2 := "cont-2"
	sb1 := "sb-1"
	sb2 := "sb-2"

	cgCont1 := CgroupID(1001)
	cgCont2 := CgroupID(1002)
	cgSb1 := CgroupID(2001)
	cgSb2 := CgroupID(2002)

	m.Add(podID1, cont1, cgCont1)
	m.Add(podID1, cont2, cgCont2)
	m.AddPodSandbox(podID1, sb1, cgSb1)

	m.AddPodSandbox(podID2, sb2, cgSb2)

	// Verify Get only retrieves regular containers
	gotCont1, ok := m.Get(cgCont1)
	assert.True(t, ok)
	assert.Equal(t, cont1, gotCont1)

	gotCont2, ok := m.Get(cgCont2)
	assert.True(t, ok)
	assert.Equal(t, cont2, gotCont2)

	_, ok = m.Get(cgSb1)
	assert.False(t, ok, "Get should not return sandbox entries")

	// Verify GetPodSandbox only retrieves pod sandboxes
	gotSb1, ok := m.GetPodSandbox(cgSb1)
	assert.True(t, ok)
	assert.Equal(t, sb1, gotSb1)

	_, ok = m.GetPodSandbox(cgCont1)
	assert.False(t, ok, "GetPodSandbox should not return container entries")

	gotSb2, ok := m.GetPodSandbox(cgSb2)
	assert.True(t, ok)
	assert.Equal(t, sb2, gotSb2)

	// Update pod1 removing cont2 and updating sandbox via UpdatePodSandbox
	newSb1 := "sb-1-new"
	cgSb1New := CgroupID(2003)
	m.Update(podID1, []ContainerID{cont1})
	m.UpdatePodSandbox(podID1, newSb1)

	// cont2 should be removed
	_, ok = m.Get(cgCont2)
	assert.False(t, ok)

	// old sb1 should be removed
	_, ok = m.GetPodSandbox(cgSb1)
	assert.False(t, ok)

	// cont1 should still be present
	gotCont1, ok = m.Get(cgCont1)
	assert.True(t, ok)
	assert.Equal(t, cont1, gotCont1)

	// Add new sandbox mapping
	m.AddPodSandbox(podID1, newSb1, cgSb1New)
	gotSb1New, ok := m.GetPodSandbox(cgSb1New)
	assert.True(t, ok)
	assert.Equal(t, newSb1, gotSb1New)

	// Pod2 should be unaffected
	gotSb2, ok = m.GetPodSandbox(cgSb2)
	assert.True(t, ok)
	assert.Equal(t, sb2, gotSb2)

	// Clear pod1
	m.Update(podID1, nil)
	m.UpdatePodSandbox(podID1, "")
	_, ok = m.Get(cgCont1)
	assert.False(t, ok)
	_, ok = m.GetPodSandbox(cgSb1New)
	assert.False(t, ok)

	// Pod2 should still be present
	gotSb2, ok = m.GetPodSandbox(cgSb2)
	assert.True(t, ok)
	assert.Equal(t, sb2, gotSb2)
}

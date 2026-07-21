// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package fsscan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

func TestPodMatcher(t *testing.T) {
	uuid := types.UID("1399d9c7-c86f-4371-8568-07b3d32258a4")
	matcher := podDirMatcher(uuid)
	require.False(t, matcher(""))
	require.True(t, matcher("pod-1399d9c7-c86f-4371-8568-07b3d32258a4"))
	require.True(t, matcher("kubepods-besteffort-pod1399d9c7_c86f_4371_8568_07b3d32258a4.slice/"))
	require.False(t, matcher("pod-000000-c86f-4371-8568-07b3d32258a4"))
}

func TestFindContainerPathRejectsEmptyContainerID(t *testing.T) {
	// an empty container id would substring-match an arbitrary cgroup
	// directory, so it must be rejected before any scanning.
	path, err := New().FindContainerPath("1399d9c7-c86f-4371-8568-07b3d32258a4", "")
	require.ErrorIs(t, err, ErrEmptyContainerID)
	require.Empty(t, path)
}

func TestFindContainerDirectoryFromRootSkipsConmon(t *testing.T) {
	root := t.TempDir()
	contID := "abc123"
	// the conmon directory sorts first in the walk; it must be skipped in favor
	// of the container's own cgroup directory.
	conmon := filepath.Join(root, "a", "crio-conmon-"+contID+".scope")
	cont := filepath.Join(root, "b", "crio-"+contID+".scope")
	require.NoError(t, os.MkdirAll(conmon, 0o755))
	require.NoError(t, os.MkdirAll(cont, 0o755))

	require.Equal(t, cont, findContainerDirectoryFromRoot(root, contID))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
)

type mockScanner struct {
	path string
	err  error
}

func (m mockScanner) FindContainerPath(types.UID, string) (string, error) { return m.path, m.err }
func (m mockScanner) FindPodPath(types.UID) (string, error)               { return "", nil }

func TestCgfsContainerPath(t *testing.T) {
	id := unmappedID{podID: uuid.New(), contID: "cont-abc"}

	t.Run("found", func(t *testing.T) {
		fn := cgfsContainerPath(mockScanner{path: "/sys/fs/cgroup/pod/cont", err: nil})
		path, err := fn(id)
		require.NoError(t, err)
		require.Equal(t, "/sys/fs/cgroup/pod/cont", path)
	})

	t.Run("soft hit without matching pod id is used", func(t *testing.T) {
		fn := cgfsContainerPath(mockScanner{path: "/sys/fs/cgroup/pod/cont", err: fsscan.ErrContainerPathWithoutMatchingPodID})
		path, err := fn(id)
		require.NoError(t, err)
		require.Equal(t, "/sys/fs/cgroup/pod/cont", path)
	})

	t.Run("hard error is propagated", func(t *testing.T) {
		wantErr := errors.New("not found")
		fn := cgfsContainerPath(mockScanner{path: "", err: wantErr})
		path, err := fn(id)
		require.ErrorIs(t, err, wantErr)
		require.Empty(t, path)
	})
}

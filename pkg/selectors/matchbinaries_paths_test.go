// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/mbset"
)

func TestParseMatchBinaryDedupesPaths(t *testing.T) {
	k := NewKernelSelectorState(nil, nil, false, 0, nil, nil)
	b := &v1alpha1.BinarySelector{
		Operator: "In",
		Values:   []string{"/usr/bin/cat", "/usr/bin/cat", "/usr/bin/echo", "/usr/bin/cat"},
	}
	require.NoError(t, ParseMatchBinary(k, b, 0, matchBinaries))

	paths := k.MatchBinariesPaths()[0]
	require.Len(t, paths, 2)
	require.Equal(t, "/usr/bin/cat", strings.TrimRight(string(paths[0][:]), "\x00"))
	require.Equal(t, "/usr/bin/echo", strings.TrimRight(string(paths[1][:]), "\x00"))
}

// nextMBSetID returns the ID the next mbset.AllocID call would hand out
func nextMBSetID(t *testing.T) uint32 {
	t.Helper()
	id, err := mbset.AllocID()
	require.NoError(t, err)
	mbset.ReleaseID(id)
	return id
}

func TestParseMatchBinaryReleasesIDOnError(t *testing.T) {
	want := nextMBSetID(t)

	k := NewKernelSelectorState(nil, nil, false, 0, nil, nil)
	b := &v1alpha1.BinarySelector{
		Operator:       "In",
		Values:         []string{"/usr/bin/cat", strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN)},
		FollowChildren: true,
	}
	require.Error(t, ParseMatchBinary(k, b, 0, matchBinaries))
	require.Equal(t, want, nextMBSetID(t))
}

func TestCreateKernelSelectorStateReleasesIDsOnError(t *testing.T) {
	want := nextMBSetID(t)

	selectors := []v1alpha1.KProbeSelector{
		{
			MatchBinaries: []v1alpha1.BinarySelector{{
				Operator:       "In",
				Values:         []string{"/usr/bin/cat"},
				FollowChildren: true,
			}},
		},
		{
			MatchBinaries: []v1alpha1.BinarySelector{{
				Operator:       "In",
				Values:         []string{strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN)},
				FollowChildren: true,
			}},
		},
	}
	parse := func(k *KernelSelectorState, s *v1alpha1.KProbeSelector, selIdx int) error {
		return ParseMatchBinaries(k, s.MatchBinaries, selIdx, matchBinaries)
	}
	_, err := createKernelSelectorState(selectors, nil, nil, false, 0, nil, nil, parse)
	require.Error(t, err)
	require.Equal(t, want, nextMBSetID(t))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fsscan

import (
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

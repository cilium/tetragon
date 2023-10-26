// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/stretchr/testify/require"
)

func TestCheckOrMountCgroup2(t *testing.T) {
	err := os.Mkdir(defaults.DefaultRunDir, os.ModeDir|0755)
	require.NoError(t, err)
	cgroup2, err := CheckOrMountCgroup2()
	require.NoError(t, err)
	require.NotEmpty(t, cgroup2)
}

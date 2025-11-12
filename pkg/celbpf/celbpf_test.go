// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>

//go:build !windows

package celbpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrue(t *testing.T) {
	insts, err := Compile("true")
	require.NoError(t, err)
	t.Logf("insts[%d]:\n%s", len(insts), insts)
}

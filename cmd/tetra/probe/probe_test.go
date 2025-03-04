// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package probe

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ProbeCommand(t *testing.T) {
	cmd := New()
	cmdOutput := &bytes.Buffer{}
	cmd.SetOut(cmdOutput)
	cmd.SetErr(io.Discard)

	cmd.Execute()

	t.Run("ContainsTrueFalse", func(t *testing.T) {
		assert.True(t, strings.Contains(cmdOutput.String(), "false") || strings.Contains(cmdOutput.String(), "true"))
	})

	t.Run("EnoughFeatureLines", func(t *testing.T) {
		assert.GreaterOrEqual(t, strings.Count(cmdOutput.String(), "\n"), 7)
	})
}

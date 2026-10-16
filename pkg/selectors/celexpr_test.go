// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCutCelAssignment(t *testing.T) {
	tests := []struct {
		in       string
		reg      string
		expr     string
		expectOk bool
	}{
		{"rdi=cel(41 + 1)", "rdi", "41 + 1", true},
		{"rdi=cel(data0 - data1 + data2)", "rdi", "data0 - data1 + data2", true},
		{"rdi=cel(and(data0, data1))", "rdi", "and(data0, data1)", true},
		{"rdi=cel(data0 == 5)", "rdi", "data0 == 5", true},
		{"edi=cel(data0)", "edi", "data0", true},
		{"rdi = cel(data0 + 1)", "rdi", "data0 + 1", true},
		{"rax=11", "", "", false},
		{"rbp=(%rsp)", "", "", false},
		{"rsp=8%rsp", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			reg, expr, ok, err := CutCelAssignment(tc.in)
			t.Logf("in=%q -> reg=%q expr=%q ok=%v err=%v", tc.in, reg, expr, ok, err)
			assert.Equal(t, tc.expectOk, ok)
			assert.Equal(t, tc.reg, reg)
			assert.Equal(t, tc.expr, expr)
			assert.NoError(t, err)
		})
	}
}

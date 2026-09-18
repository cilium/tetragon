// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api"
)

func TestArgsDecoder(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		flags    uint32
		wantArgs string
		wantCWD  string
	}{
		{"args and cwd", "a\x00b\x00/home", 0, "a b", "/home"},
		{"quoted arg", "-c\x00echo a b\x00/", 0, `-c "echo a b"`, "/"},
		{"leading quoted arg", "a b\x00c\x00/", 0, ` "a b" c`, "/"},
		{"empty first arg", "\x00b\x00/", 0, "b", "/"},
		{"no cwd support", "a\x00b", api.EventNoCWDSupport, "a b", ""},
		{"root cwd", "a\x00b", api.EventRootCWD, "a b", "/"},
		{"trailing nuls", "a\x00b\x00/tmp\x00\x00", 0, "a b", "/tmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, cwd := ArgsDecoder(tt.in, tt.flags)
			require.Equal(t, tt.wantArgs, args)
			require.Equal(t, tt.wantCWD, cwd)
		})
	}
}

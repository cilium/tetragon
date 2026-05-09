// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package program

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiUprobeAttachPaths(t *testing.T) {
	data := &MultiUprobeAttachData{
		Attach: map[string]*MultiUprobeAttachSymbolsCookies{
			"/usr/bin/zsh":  {},
			"/usr/bin/bash": {},
			"/usr/bin/dash": {},
		},
	}

	assert.Equal(t, []string{"/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh"}, multiUprobeAttachPaths(data))
}

func TestMultiUprobeLinkPinExtras(t *testing.T) {
	assert.Empty(t, multiUprobeLinkPinExtras("/usr/bin/bash", 1))

	extras := multiUprobeLinkPinExtras("/usr/bin/my shell", 2, "sleepable")
	require.Len(t, extras, 2)
	assert.Equal(t, "sleepable", extras[0])
	assert.Contains(t, extras[1], "my_shell")
	assert.False(t, strings.ContainsAny(extras[1], "/ "))

	otherExtras := multiUprobeLinkPinExtras("/tmp/my shell", 2, "sleepable")
	require.Len(t, otherExtras, 2)
	assert.NotEqual(t, extras[1], otherExtras[1])
}

func TestValidateMultiUprobeAttach(t *testing.T) {
	tests := []struct {
		name    string
		attach  *MultiUprobeAttachSymbolsCookies
		wantErr string
	}{
		{
			name: "symbols",
			attach: &MultiUprobeAttachSymbolsCookies{
				Symbols: []string{"main", "helper"},
				Offsets: []uint64{0, 4},
				Cookies: []uint64{1, 2},
			},
		},
		{
			name:    "nil",
			wantErr: "missing attach data",
		},
		{
			name: "symbols and addresses",
			attach: &MultiUprobeAttachSymbolsCookies{
				Symbols:   []string{"main"},
				Addresses: []uint64{1},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "cookie mismatch",
			attach: &MultiUprobeAttachSymbolsCookies{
				Symbols: []string{"main", "helper"},
				Cookies: []uint64{1},
			},
			wantErr: "cookies length 1 does not match target count 2",
		},
		{
			name: "refctr mismatch",
			attach: &MultiUprobeAttachSymbolsCookies{
				Addresses:     []uint64{1, 2},
				RefCtrOffsets: []uint64{1},
			},
			wantErr: "ref_ctr_offsets length 1 does not match target count 2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateMultiUprobeAttach("/bin/test", test.attach)
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

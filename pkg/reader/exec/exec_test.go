// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/api"
)

func TestDecodeCommonFlags(t *testing.T) {
	type args struct {
		flags uint32
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty",
			args: args{flags: 0},
			want: "",
		},
		{
			name: "multiple flags",
			args: args{flags: api.EventExecve | api.EventProcFS},
			want: "execve procFS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(DecodeCommonFlags(tt.args.flags), " "); got != tt.want {
				t.Errorf("DecodCommonFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"strings"
	"testing"

	"github.com/isovalent/tetragon-oss/pkg/api"
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
			// nolint We still want to support this even though it's deprecated
			args: args{flags: api.EventExecve | api.EventExecveAt | api.EventProcFS},
			want: "execve execveat procFS",
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

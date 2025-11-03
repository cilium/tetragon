// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import (
	"io"
	"strings"
	"testing"
)

var mapFDinfo = strings.NewReader(`pos:    0
flags:  02000002
mnt_id: 16
ino:    65
map_type:       6
key_size:       4
value_size:     12288
max_entries:    1
map_flags:      0x0
map_extra:      0x0
memlock:        74056`)

func Benchmark_parseMemlockFromFDInfoReader(b *testing.B) {
	for b.Loop() {
		parseMemlockFromFDInfoReader(mapFDinfo)
	}
}

func Test_parseMemlockFromFDInfoReader(t *testing.T) {
	tests := []struct {
		name    string
		args    io.Reader
		want    int
		wantErr bool
	}{
		{
			name:    "mapfdinfo",
			args:    mapFDinfo,
			want:    74056,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMemlockFromFDInfoReader(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMemlockFromFDInfoReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseMemlockFromFDInfoReader() = %v, want %v", got, tt.want)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"fmt"
	"testing"
)

func TestHumanizeByteCount(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0 B"},
		{2, "2 B"},
		{999, "999 B"},
		{1000, "1.00 kB"},
		{1025, "1.02 kB"}, // rounding is a bit off but that's okay
		{1026, "1.03 kB"},
		{4458824, "4.46 MB"},
		{987654321, "987.65 MB"},
		{1010000000, "1.01 GB"},
		{12970000000000, "12.97 TB"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			if got := HumanizeByteCount(tt.input); got != tt.want {
				t.Errorf("HumanizeByteCount(%d) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

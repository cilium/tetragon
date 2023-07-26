// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"testing"
)

func Fuzz_parseString(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte) {
		reader := bytes.NewReader(input)
		parseString(reader)
	})
}

func Test_parseString(t *testing.T) {
	tests := []struct {
		name    string
		input   bytes.Reader
		want    string
		wantErr bool
	}{
		{"normal", *bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "pizza", false},
		{"shortened", *bytes.NewReader([]byte{3, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "piz", false},
		{"too large", *bytes.NewReader([]byte{0, 0, 0, 1, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"error code -2", *bytes.NewReader([]byte{254, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"negative size", *bytes.NewReader([]byte{253, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"missing content", *bytes.NewReader([]byte{1, 0, 0, 0}), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseString(&tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error = %s, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("remove trailing null byte", func(t *testing.T) {
		out, err := parseString(bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}))
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if out != "pizza" {
			t.Errorf("got %q, want %q", out, "pizza")
		}
	})
}

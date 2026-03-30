// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"
)

func TestGoABISlotForArg(t *testing.T) {
	tests := []struct {
		symbol    string
		argIndex  int
		wantSlot  int
		wantFound bool
	}{
		{"net/http.ServeContent", 0, 0, true},
		{"net/http.ServeContent", 1, 2, true},
		{"net/http.ServeContent", 2, 3, true},
		{"net/http.ServeContent", 3, 5, true},
		{"net/http.ServeContent", 4, 8, true},
		{"path/filepath.Clean", 0, 0, true},
		{"os.Open", 0, 0, true},
		{"unknown.Func", 0, -1, false},
		{"net/http.ServeContent", 99, -1, false},
	}
	for _, tt := range tests {
		got := GoABISlotForArg(tt.symbol, tt.argIndex)
		found := got >= 0
		if found != tt.wantFound || (found && got != tt.wantSlot) {
			t.Errorf("GoABISlotForArg(%q, %d) = %d (found=%v), want %d (found=%v)",
				tt.symbol, tt.argIndex, got, found, tt.wantSlot, tt.wantFound)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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

func TestExpandClearGoStringActions(t *testing.T) {
	spec := &v1alpha1.UProbeSpec{
		Symbols: []string{"net/http.Get"},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchActions: []v1alpha1.ActionSelector{{
				Action:   "ClearGoString",
				ArgIndex: 0,
			}},
		}},
	}
	if err := expandClearGoStringActions(spec); err != nil {
		t.Fatalf("expandClearGoStringActions: %v", err)
	}
	action := spec.Selectors[0].MatchActions[0]
	if strings.ToLower(action.Action) != "override" {
		t.Fatalf("expected action Override, got %s", action.Action)
	}
	if len(action.ArgRegs) != 1 {
		t.Fatalf("expected 1 argReg, got %d", len(action.ArgRegs))
	}
	if action.ArgRegs[0] != "rbx=0" {
		t.Fatalf("expected [rbx=0], got %v", action.ArgRegs)
	}
}

func TestExpandClearGoStringActionsServeContent(t *testing.T) {
	spec := &v1alpha1.UProbeSpec{
		Symbols: []string{"net/http.ServeContent"},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchActions: []v1alpha1.ActionSelector{{
				Action:   "ClearGoString",
				ArgIndex: 2,
			}},
		}},
	}
	if err := expandClearGoStringActions(spec); err != nil {
		t.Fatalf("expandClearGoStringActions: %v", err)
	}
	action := spec.Selectors[0].MatchActions[0]
	if strings.ToLower(action.Action) != "override" {
		t.Fatalf("expected action Override, got %s", action.Action)
	}
	// arg 2 (name), slot 3, rdi/rsi — only length register is cleared
	if len(action.ArgRegs) != 1 || action.ArgRegs[0] != "rsi=0" {
		t.Fatalf("expected [rsi=0], got %v", action.ArgRegs)
	}
}

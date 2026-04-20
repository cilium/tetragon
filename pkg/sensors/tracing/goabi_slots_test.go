// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"reflect"
	"runtime"
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
		{"github.com/cilium/tetragon/pkg/sensors/tracing/goabitest.ReportLenForABI", 0, 0, true},
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
	if runtime.GOARCH != "amd64" {
		t.Skip("go_string ABI register mapping is amd64-only")
	}
	tests := []struct {
		symbol   string
		argIndex uint32
		wantRegs []string
	}{
		{"net/http.Get", 0, []string{"rbx=0"}},
		{"net/http.ServeContent", 2, []string{"rsi=0"}},
	}
	for _, tt := range tests {
		spec := &v1alpha1.UProbeSpec{
			Symbols: []string{tt.symbol},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchActions: []v1alpha1.ActionSelector{{
					Action:        "Override",
					ClearGoString: true,
					ArgIndex:      tt.argIndex,
				}},
			}},
		}
		if err := expandClearGoStringActions(spec); err != nil {
			t.Errorf("expandClearGoStringActions(%s, arg %d): %v", tt.symbol, tt.argIndex, err)
			continue
		}
		act := spec.Selectors[0].MatchActions[0]
		if act.ClearGoString {
			t.Errorf("%s arg %d: ClearGoString not cleared after expansion", tt.symbol, tt.argIndex)
		}
		if !reflect.DeepEqual(act.ArgRegs, tt.wantRegs) {
			t.Errorf("%s arg %d: ArgRegs = %v, want %v", tt.symbol, tt.argIndex, act.ArgRegs, tt.wantRegs)
		}
	}
}

func TestExpandClearGoStringActionsErrors(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("go_string ABI register mapping is amd64-only")
	}
	mk := func(symbol string) *v1alpha1.UProbeSpec {
		return &v1alpha1.UProbeSpec{
			Symbols: []string{symbol},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchActions: []v1alpha1.ActionSelector{{
					Action:        "Override",
					ClearGoString: true,
				}},
			}},
		}
	}
	wrongAction := mk("net/http.Get")
	wrongAction.Selectors[0].MatchActions[0].Action = "Post"

	withArgRegs := mk("net/http.Get")
	withArgRegs.Selectors[0].MatchActions[0].ArgRegs = []string{"rax=0"}

	multiSym := mk("net/http.Get")
	multiSym.Symbols = append(multiSym.Symbols, "net/http.Post")

	tests := []struct {
		name string
		spec *v1alpha1.UProbeSpec
	}{
		{"wrong action", wrongAction},
		{"argRegs already set", withArgRegs},
		{"multiple symbols", multiSym},
		{"unknown symbol", mk("unknown.Func")},
	}
	for _, tt := range tests {
		if err := expandClearGoStringActions(tt.spec); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

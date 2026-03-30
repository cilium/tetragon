// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"go/types"
	"testing"
)

type unknownType struct{}

func (u unknownType) Underlying() types.Type {
	return u
}

func (unknownType) String() string {
	return "unknown"
}

func TestIntRegSlots(t *testing.T) {
	if n, err := intRegSlots(types.Typ[types.String]); err != nil || n != 2 {
		t.Fatalf("string: got (%d, %v), want (2, nil)", n, err)
	}

	if _, err := intRegSlots(unknownType{}); err == nil {
		t.Fatal("expected error for unsupported type, got nil")
	}
}

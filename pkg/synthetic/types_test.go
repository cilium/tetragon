// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic_test

import (
	"reflect"
	"testing"

	"github.com/cilium/tetragon/pkg/synthetic"
)

func TestRegisterType(t *testing.T) {
	type newType struct {
		Field string `json:"field"`
	}

	// Register new type
	synthetic.RegisterType((*newType)(nil))

	// Verify it's registered (can marshal/unmarshal)
	original := &newType{Field: "test"}
	codec := synthetic.Serializer{}
	data, err := codec.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	result, err := codec.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(result, original) {
		t.Errorf("result = %#v, want %#v", result, original)
	}
}

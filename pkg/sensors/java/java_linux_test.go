// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	api "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestValidate(t *testing.T) {
	valid := func() *api.JavaPolicySpec {
		return &api.JavaPolicySpec{
			Executables: []string{"/usr/bin/java"},
			Patches: []api.JavaClassPatch{{
				Signature:   "Lcom/example/Handler;",
				Replacement: []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52},
				Rollback:    []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52},
			}},
		}
	}
	if err := validate(valid()); err != nil {
		t.Fatalf("validate(valid policy) error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*api.JavaPolicySpec)
		wantErr string
	}{
		{name: "relative executable", mutate: func(s *api.JavaPolicySpec) { s.Executables[0] = "java" }, wantErr: "absolute and cleaned"},
		{name: "unclean executable", mutate: func(s *api.JavaPolicySpec) { s.Executables[0] = "/usr/bin/../bin/java" }, wantErr: "absolute and cleaned"},
		{name: "empty argument token", mutate: func(s *api.JavaPolicySpec) { s.ProcessArgsContains = []string{""} }, wantErr: "non-empty"},
		{name: "invalid signature", mutate: func(s *api.JavaPolicySpec) { s.Patches[0].Signature = "Lcom.example.Handler;" }, wantErr: "not a JVM object signature"},
		{name: "duplicate signature", mutate: func(s *api.JavaPolicySpec) { s.Patches = append(s.Patches, s.Patches[0]) }, wantErr: "duplicate Java class signature"},
		{name: "bad class magic", mutate: func(s *api.JavaPolicySpec) { s.Patches[0].Replacement[0] = 0 }, wantErr: "must be Java class files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := valid()
			tt.mutate(spec)
			err := validate(spec)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeManifestApplyAndRollback(t *testing.T) {
	patches := []api.JavaClassPatch{{
		Signature:   "Lcom/example/Handler;",
		Replacement: []byte{0xca, 0xfe, 0xba, 0xbe, 1, 2},
		Rollback:    []byte{0xca, 0xfe, 0xba, 0xbe, 3, 4, 5},
	}}

	for _, tt := range []struct {
		name     string
		rollback bool
		want     []byte
	}{
		{name: "apply", want: patches[0].Replacement},
		{name: "rollback", rollback: true, want: patches[0].Rollback},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeManifest(patches, tt.rollback)
			if err != nil {
				t.Fatalf("encodeManifest() error = %v", err)
			}
			if !bytes.HasPrefix(got, []byte(manifestMagic)) {
				t.Fatalf("manifest magic = %q, want %q", got[:len(manifestMagic)], manifestMagic)
			}
			if count := binary.BigEndian.Uint32(got[len(manifestMagic):]); count != 1 {
				t.Fatalf("patch count = %d, want 1", count)
			}
			offset := len(manifestMagic) + 4
			sigLen := int(binary.BigEndian.Uint16(got[offset:]))
			classLen := int(binary.BigEndian.Uint32(got[offset+2:]))
			offset += 6
			if signature := string(got[offset : offset+sigLen]); signature != patches[0].Signature {
				t.Fatalf("class signature = %q, want %q", signature, patches[0].Signature)
			}
			offset += sigLen
			if !bytes.Equal(got[offset:offset+classLen], tt.want) {
				t.Fatalf("class bytes = %v, want %v", got[offset:offset+classLen], tt.want)
			}
		})
	}
}

func TestContainsArgs(t *testing.T) {
	cmdline := []byte("/usr/bin/java\x00-Xmx1g\x00com.example.Server\x00")
	if !containsArgs(cmdline, []string{"com.example", "-Xmx"}) {
		t.Fatal("containsArgs() rejected tokens present in separate arguments")
	}
	if containsArgs(cmdline, []string{"com.example", "missing"}) {
		t.Fatal("containsArgs() accepted a missing token")
	}
	if !containsArgs(cmdline, nil) {
		t.Fatal("containsArgs() rejected an empty token list")
	}
}

func TestValidSignature(t *testing.T) {
	for _, signature := range []string{"Lcom/example/Handler;", "Ljava/lang/String;"} {
		if !validSignature(signature) {
			t.Errorf("validSignature(%q) = false", signature)
		}
	}
	for _, signature := range []string{"", "com/example/Handler", "Lcom.example.Handler;", "Lcom//Handler;", "[Ljava/lang/String;"} {
		if validSignature(signature) {
			t.Errorf("validSignature(%q) = true", signature)
		}
	}
}

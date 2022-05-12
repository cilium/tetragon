// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package bpf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewBtfError(t *testing.T) {
	_, err := NewBTF("/path/that/does/not/exist")
	if err == nil {
		t.FailNow()
	}
}

func TestBtf54(t *testing.T) {
	_, testFname, _, _ := runtime.Caller(0)
	btfPath := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata", "btf", "vmlinux-5.4.104+")
	if _, err := os.Stat(btfPath); err != nil {
		t.Skip(fmt.Sprintf("%s not found", btfPath))
	}
	btf, err := NewBTF(btfPath)
	if err != nil {
		t.Fatalf("failed to initialize BTF: %s", err)
	}
	defer btf.Close()

	_, err = btf.FindByName("this should not exist")
	if err == nil {
		t.Fatal("FindByName() should have returned an error")
	}

	funcId, err := btf.FindByNameKind("__x64_sys_lseek", BtfKindFunc)
	if err != nil {
		t.Fatalf("__x64_sys_lseek function was not found: %s", err)
	}
	funcTy, err := btf.TypeByID(funcId)
	if err != nil {
		t.Fatalf("failed to to find type by id: %s", err)
	}

	funcProtoTyID, err := btf.UnderlyingType(funcTy)
	if err != nil {
		t.Fatalf("Unable to get function's type: %s", err)
	}
	s, err := btf.DumpTy(funcProtoTyID)
	if err != nil {
		t.Fatalf("Dump failed")
	}
	if s != "long int(const struct pt_regs *regs)" {
		t.Fatalf("unexpected function signature: %s", s)
	}

	funcProtoTy, _ := btf.TypeByID(funcProtoTyID)
	p0Name, _ := btf.ParamName(funcProtoTy, 0)
	if p0Name != "regs" {
		t.Fatalf("unexpected parameter name: %s", p0Name)
	}

	retTyID, _ := btf.UnderlyingType(funcProtoTy)
	s, _ = btf.DumpTy(retTyID)
	if s != "long int" {
		t.Fatalf("unexpected function return type: %s", s)
	}
}

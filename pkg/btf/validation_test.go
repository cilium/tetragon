// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package btf

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func expectError(t *testing.T, err error) error {
	if err == nil {
		return errors.New("validation should have failed, but did not")
	}
	// NB: eventually it would be good if we check that the error the
	// specific error we expect. For now, we just print the erorr so that
	// we can  inspect it.
	t.Logf("Got an error as expected: %s", err)
	return nil
}
func expectOK(_ *testing.T, err error) error {
	if err != nil {
		return err
	}
	return nil
}

var testFiles = []struct {
	specFname string
	checkFn   func(t *testing.T, err error) error
}{
	{specFname: "specs/nosuchcall.yaml", checkFn: expectError},
	{specFname: "specs/notasyscall.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/syslseek.yaml", checkFn: expectOK},
	{specFname: "specs/wrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/wrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/lseek.yaml", checkFn: expectOK},
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
}

func genericTestSpecs(ks *ksyms.Ksyms, testdataPath string, btfFName string) func(*testing.T) {
	return func(t *testing.T) {
		if _, err := os.Stat(btfFName); err != nil {
			t.Skipf("%q not found", btfFName)
		}
		btf, err := btf.LoadSpec(btfFName)
		if err != nil {
			t.Fatalf("failed to initialize BTF: %s", err)
		}

		for fi := range testFiles {
			specFname := testFiles[fi].specFname
			t.Run(specFname, func(t *testing.T) {
				specFname := filepath.Join(testdataPath, specFname)
				tp, err := tracingpolicy.FromFile(specFname)
				if err != nil {
					t.Fatal(err)
				}
				spec := tp.TpSpec()
				for ki := range spec.KProbes {
					err = ValidateKprobeSpec(btf, spec.KProbes[ki].Call, &spec.KProbes[ki], ks)
					if checkErr := testFiles[fi].checkFn(t, err); checkErr != nil {
						t.Fatal(checkErr)
					}
				}
			})
		}
	}
}

func TestSpecs(t *testing.T) {
	_, testFname, _, _ := runtime.Caller(0)
	testdataPath := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata")

	// get kernel symbols
	ks, err := ksyms.KernelSymbols()
	if err != nil {
		t.Fatalf("validateKprobeSpec: ksyms.KernelSymbols: %s", err)
	}

	btfFiles, err := listBTFFiles()
	fatalOnError(t, err)

	for _, btfFile := range btfFiles {
		// An extra "/" is added to enhance test name readability
		t.Run(btfFile+"/", genericTestSpecs(ks, testdataPath, btfFile))
	}
}

func TestEnum(t *testing.T) {
	require.Equal(t,
		"u16", getKernelType(&btf.Enum{
			Size:   2,
			Signed: false,
		}))
	require.Equal(t,
		"s32", getKernelType(&btf.Enum{
			Size:   4,
			Signed: true,
		}))
}

// gcc and clang spell some integer types differently in DWARF, and so in the
// BTF pahole derives from it: a kernel built with LLVM=1 reports "long" where a
// gcc-built one reports "long int". Both spellings must behave identically.
func TestTypesCompatibleAcrossCompilers(t *testing.T) {
	for _, tc := range []struct {
		gcc, clang string // spelling in a gcc- and a clang-built kernel
		specTy     string // MatchArgs type both spellings must satisfy, if any
	}{
		// spelled differently by the two compilers
		{gcc: "long int", clang: "long", specTy: "int64"},
		{gcc: "long unsigned int", clang: "unsigned long", specTy: "uint64"},
		{gcc: "short int", clang: "short", specTy: "int16"},
		{gcc: "short unsigned int", clang: "unsigned short", specTy: "uint16"},
		{gcc: "long long int", clang: "long long"},
		{gcc: "long long unsigned int", clang: "unsigned long long"},

		// spelled the same by both, or not an integer at all
		{gcc: "int", clang: "int", specTy: "int32"},
		{gcc: "unsigned int", clang: "unsigned int", specTy: "uint32"},
		{gcc: "unsigned char", clang: "unsigned char", specTy: "uint8"},
		{gcc: "char", clang: "char", specTy: "int8"},
		{gcc: "size_t", clang: "size_t", specTy: "size_t"},
		{gcc: "umode_t", clang: "umode_t", specTy: "uint16"},
		{gcc: "const char *", clang: "const char *", specTy: "string"},
		{gcc: "struct file *", clang: "struct file *", specTy: "file"},
		{gcc: "signed char", clang: "signed char"},
		{gcc: "_Bool", clang: "_Bool"},
	} {
		t.Run(tc.gcc, func(t *testing.T) {
			require.Equal(t, tc.clang, canonicalKernelType(tc.gcc))
			require.Equal(t, tc.clang, canonicalKernelType(tc.clang))

			if tc.specTy == "" {
				return
			}
			require.True(t, typesCompatible(tc.specTy, tc.gcc), "gcc spelling %q", tc.gcc)
			require.True(t, typesCompatible(tc.specTy, tc.clang), "clang spelling %q", tc.clang)
		})
	}
}

func TestValidateSyscallReturnTypeAcrossCompilers(t *testing.T) {
	const call = "__x64_sys_setns"

	// BTF for `<retName> __x64_sys_setns(const struct pt_regs *)`, the shape
	// ValidateKprobeSpec expects for a `syscall: true` spec.
	syscallWrapperBTF := func(t *testing.T, retName string) *btf.Spec {
		t.Helper()

		fn := &btf.Func{
			Name:    call,
			Linkage: btf.StaticFunc,
			Type: &btf.FuncProto{
				Return: &btf.Int{Name: retName, Size: 8, Encoding: btf.Signed},
				Params: []btf.FuncParam{{
					Name: "regs",
					Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: "pt_regs"}}},
				}},
			},
		}

		b, err := btf.NewBuilder([]btf.Type{fn}, nil)
		require.NoError(t, err)
		raw, err := b.Marshal(nil, nil)
		require.NoError(t, err)
		spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
		require.NoError(t, err)
		return spec
	}

	// setns(int fd, int flags), as in the docs' deny-namespace-access policy.
	kspec := func() *v1alpha1.KProbeSpec {
		return &v1alpha1.KProbeSpec{
			Call:    "sys_setns",
			Syscall: true,
			Args: []v1alpha1.KProbeArg{
				{Index: 0, Type: "int"},
				{Index: 1, Type: "int"},
			},
		}
	}

	// Empty table => GetKmod() reports "not a module", as for setns on a real
	// host, so the spec we pass in is the one validated.
	ks := &ksyms.Ksyms{}

	t.Run("gcc", func(t *testing.T) {
		require.NoError(t, ValidateKprobeSpec(syscallWrapperBTF(t, "long int"), call, kspec(), ks))
	})

	t.Run("clang", func(t *testing.T) {
		require.NoError(t, ValidateKprobeSpec(syscallWrapperBTF(t, "long"), call, kspec(), ks))
	})

	// A genuinely non-long return is still rejected, and named in the error.
	t.Run("rejects non-long", func(t *testing.T) {
		err := ValidateKprobeSpec(syscallWrapperBTF(t, "int"), call, kspec(), ks)
		require.ErrorContains(t, err, "syscall return type is not long")
		require.ErrorContains(t, err, `"int"`)
	})
}

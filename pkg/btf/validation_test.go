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

// A gcc-built kernel exposes "long int" where an LLVM=1 one exposes "long".
// Both must validate identically. See github.com/cilium/tetragon/issues/5598.

func TestCanonicalKernelType(t *testing.T) {
	for _, tc := range []struct{ gcc, clang string }{
		{"long int", "long"},
		{"long unsigned int", "unsigned long"},
		{"long long int", "long long"},
		{"long long unsigned int", "unsigned long long"},
		{"short int", "short"},
		{"short unsigned int", "unsigned short"},
	} {
		require.Equal(t, tc.clang, canonicalKernelType(tc.gcc))
		require.Equal(t, tc.clang, canonicalKernelType(tc.clang))
	}

	// Spelled the same by both compilers, or not an integer: pass through.
	for _, same := range []string{
		"char", "signed char", "unsigned char", "int", "unsigned int", "_Bool",
		"void *", "const char *", "struct file *", "size_t", "umode_t",
	} {
		require.Equal(t, same, canonicalKernelType(same))
	}
}

func TestTypesCompatibleAcrossCompilers(t *testing.T) {
	for _, tc := range []struct {
		specTy     string
		gcc, clang string
	}{
		{"int64", "long int", "long"},
		{"uint64", "long unsigned int", "unsigned long"},
		{"int16", "short int", "short"},
		{"uint16", "short unsigned int", "unsigned short"},
	} {
		t.Run(tc.specTy, func(t *testing.T) {
			require.True(t, typesCompatible(tc.specTy, tc.gcc), "gcc spelling %q", tc.gcc)
			require.True(t, typesCompatible(tc.specTy, tc.clang), "clang spelling %q", tc.clang)
		})
	}
}

// syscallWrapperBTF builds BTF for `<retName> <call>(const struct pt_regs *)`,
// the shape ValidateKprobeSpec expects for a `syscall: true` spec.
func syscallWrapperBTF(t *testing.T, call, retName string) *btf.Spec {
	t.Helper()

	ret := &btf.Int{Name: retName, Size: 8, Encoding: btf.Signed}
	fn := &btf.Func{
		Name:    call,
		Linkage: btf.StaticFunc,
		Type: &btf.FuncProto{
			Return: ret,
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

func TestValidateSyscallReturnTypeAcrossCompilers(t *testing.T) {
	const call = "__x64_sys_setns"

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
		err := ValidateKprobeSpec(syscallWrapperBTF(t, call, "long int"), call, kspec(), ks)
		require.NoError(t, err)
	})

	t.Run("clang", func(t *testing.T) {
		err := ValidateKprobeSpec(syscallWrapperBTF(t, call, "long"), call, kspec(), ks)
		require.NoError(t, err)
	})

	// A genuinely non-long return is still rejected, and named in the error.
	t.Run("rejects non-long", func(t *testing.T) {
		err := ValidateKprobeSpec(syscallWrapperBTF(t, call, "int"), call, kspec(), ks)
		require.ErrorContains(t, err, "syscall return type is not long")
		require.ErrorContains(t, err, `"int"`)
	})
}

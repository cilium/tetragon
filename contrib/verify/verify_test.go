// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/selectors"
)

var (
	tetragonDir = flag.String("tetragon-dir", defaults.DefaultTetragonLib, "Directory containing Tetragon BPF objects")
	debug       = flag.Bool("debug", false, "Enable debug output")
)

func TestVerifyTetragonPrograms(t *testing.T) {
	require.NoError(t, btf.InitCachedBTF(*tetragonDir, ""), "failed to initialize kernel BTF")

	files, err := os.ReadDir(*tetragonDir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	selectedFiles := selectKernelVersionFilesForTest(t, files)

	for _, file := range files {
		fileName := file.Name()
		if file.IsDir() || filepath.Ext(fileName) != ".o" {
			continue
		}

		// Alignchecker is not a bpf program, so ignore it
		if strings.HasPrefix(fileName, "bpf_alignchecker") {
			continue
		}

		// Generic tracepoint needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_tracepoint") {
			continue
		}

		// Multi kprobe support is still not widely around, skip the object
		if strings.HasPrefix(fileName, "bpf_multi_") {
			t.Logf("%s ⊘ (multi-kprobe)", fileName)
			continue
		}

		// Can't load fentry/fexit objects without loader setup
		if strings.HasPrefix(fileName, "bpf_generic_fentry") ||
			strings.HasPrefix(fileName, "bpf_generic_fexit") {
			t.Logf("%s ⊘ (fentry/fexit)", fileName)
			continue
		}

		// Skip rhel7 objects, it's special
		if strings.HasSuffix(fileName, "310.o") {
			t.Logf("%s ⊘ (rhel7)", fileName)
			continue
		}

		// Skip kernel version-specific objects if not selected for current kernel
		if selectedFiles != nil && extractKernelVersion(fileName) != "" && !selectedFiles[fileName] {
			continue
		}

		// Skip bpf_loader for kernel < 5.19
		if strings.HasPrefix(fileName, "bpf_loader") && !kernels.MinKernelVersion("5.19") {
			t.Logf("%s ⊘ (requires kernel 5.19)", fileName)
			continue
		}

		// Generic LSM BPF needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_lsm") {
			t.Logf("%s ⊘ (lsm)", fileName)
			continue
		}

		// Check if bpf_override_return is available
		if strings.HasPrefix(fileName, "bpf_generic_kprobe") || strings.HasPrefix(fileName, "bpf_enforcer") {
			if err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnOverrideReturn); err != nil {
				t.Logf("%s ⊘ (no bpf_override_return)", fileName)
				continue
			}
		}

		// Check if uprobe regs change is available
		if strings.HasPrefix(fileName, "bpf_generic_uprobe") && !bpf.HasUprobeRegsChange() {
			t.Logf("%s ⊘ (no uprobe regs change)", fileName)
			continue
		}

		// Check if bpf_copy_from_user_str is available
		if (strings.HasPrefix(fileName, "bpf_generic_uprobe") ||
			strings.HasPrefix(fileName, "bpf_generic_usdt")) &&
			!bpf.HasKfunc("bpf_copy_from_user_str") {
			t.Logf("%s ⊘ (no bpf_copy_from_user_str)", fileName)
			continue
		}

		spec, err := ebpf.LoadCollectionSpec(*tetragonDir + "/" + fileName)
		require.NoError(t, err, "failed to parse elf file into collection spec")
		require.NotNil(t, spec, "collection spec should not be nil")

		// The filter_arg programs call cel_expr_N functions generated at policy
		// load time. The base (4.19) objects have no such calls.
		if fileName != "bpf_generic_kprobe.o" && fileName != "bpf_generic_uprobe.o" {
			for _, prog := range spec.Programs {
				if prog.Name == "generic_kprobe_filter_arg" || prog.Name == "generic_uprobe_filter_arg" {
					var exprs selectors.CelExprFunctions
					err := exprs.RewriteProg(prog)
					require.NoError(t, err, "failed to rewrite program for empty CEL expressions")
				}
			}
		}

		collection, err := ebpf.NewCollection(spec)
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) && *debug {
				t.Logf("%+v", ve)
			}
			_, kver, _ := kernels.GetKernelVersion("", "/proc")
			t.Errorf("%s ✗: failed to load object on kernel %s: %v", fileName, kver, err)
			continue
		}

		collection.Close()
		t.Logf("%s ✓", fileName)
	}
}

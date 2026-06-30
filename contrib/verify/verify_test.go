// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/selectors"
)

const (
	tetragondir = "/var/lib/tetragon"
)

func TestVerifyTetragonPrograms(t *testing.T) {

	// Init the BTF cache like the agent does, otherwise bpf.HasKfunc() always
	// returns false and we'd verify a different variant than production loads.
	require.NoError(t, btf.InitCachedBTF("", ""), "failed to initialize BTF cache")

	tetragonDir := os.Getenv("TETRAGONDIR")
	if tetragonDir == "" {
		tetragonDir = tetragondir
	}

	files, err := os.ReadDir(tetragonDir)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	for _, file := range files {
		fileName := file.Name()
		if file.IsDir() || filepath.Ext(fileName) != ".o" {
			continue
		}

		// Alignchecker is not a bpf program, so ignore it
		if strings.HasPrefix(fileName, "bpf_alignchecker") {
			continue
		}

		// Globals is just for testing, so ignore it
		if strings.HasPrefix(fileName, "bpf_alignchecker") {
			continue
		}

		// Generic tracepoint needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_tracepoint") {
			continue
		}

		// Multi kprobe support is still not widely around, skip the object
		if strings.HasPrefix(fileName, "bpf_multi_") {
			continue
		}

		// Can't load fentry/fexit objects without loader setup
		if strings.HasPrefix(fileName, "bpf_generic_fentry") ||
			strings.HasPrefix(fileName, "bpf_generic_fexit") {
			continue
		}

		// Skip v6.1 objects check for kernel < 6.1
		if strings.HasSuffix(fileName, "61.o") && !kernels.MinKernelVersion("6.1") {
			continue
		}

		// Skip v5.11 objects check for kernel < 5.11
		if strings.HasSuffix(fileName, "511.o") && !kernels.MinKernelVersion("5.11") {
			continue
		}

		// On >=6.1 kernels the loader selects the v6.1 variant, so the v5.11
		// build of the same object is never loaded there. Verifying it would
		// pair v5.11 with a CONFIG_ITER_NUM value production never uses for it
		// and cross the 1M-instruction verifier limit, so skip it when a v6.1
		// counterpart exists.
		if strings.HasSuffix(fileName, "_v511.o") && kernels.MinKernelVersion("6.1") {
			v61 := strings.TrimSuffix(fileName, "_v511.o") + "_v61.o"
			if _, err := os.Stat(filepath.Join(tetragonDir, v61)); err == nil {
				continue
			}
		}

		// Skip rhel7 objects, it's special
		if strings.HasSuffix(fileName, "310.o") {
			continue
		}

		// Skip bpf_loader for kernel < 5.19
		if strings.HasPrefix(fileName, "bpf_loader") && !kernels.MinKernelVersion("5.19") {
			continue
		}

		// Generic LSM BPF needs more complex userspace logic to load, so ignore it
		if strings.HasPrefix(fileName, "bpf_generic_lsm") {
			continue
		}

		// Check if bpf_override_return is available
		if strings.HasPrefix(fileName, "bpf_generic_kprobe") || strings.HasPrefix(fileName, "bpf_enforcer") {
			if err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnOverrideReturn); err != nil {
				continue
			}
		}

		// Check if uprobe regs change is available
		if strings.HasPrefix(fileName, "bpf_generic_uprobe") && !bpf.HasUprobeRegsChange() {
			continue
		}

		// Check if bpf_copy_from_user_str is available
		if (strings.HasPrefix(fileName, "bpf_generic_uprobe") ||
			strings.HasPrefix(fileName, "bpf_generic_usdt")) &&
			!bpf.HasKfunc("bpf_copy_from_user_str") {
			continue
		}

		spec, err := ebpf.LoadCollectionSpec(tetragonDir + "/" + fileName)
		require.NoError(t, err, "failed to parse elf file into collection spec")
		require.NotNil(t, spec, "collection spec should not be nil")

		if isDebugEnabled() {
			fmt.Printf("[%s]\n", fileName)
			for _, progSpec := range spec.Programs {
				fmt.Printf("%s\n", progSpec.Instructions.String())
			}
		}

		// Resolve cel_expr references the way the agent does at load time:
		// rewrite any program that references a cel_expr function.
		for _, prog := range spec.Programs {
			if !programReferencesCelExpr(prog) {
				continue
			}
			var exprs selectors.CelExprFunctions
			err := exprs.RewriteProg(prog)
			require.NoError(t, err, "failed to rewrite program %s for empty CEL expressions", prog.Name)
		}

		require.NoError(t, rewriteConfigConstants(spec), "failed to set CONFIG_ITER_NUM")

		collection, err := ebpf.NewCollection(spec)
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				fmt.Printf("%+v\n", ve)

				_, kver, _ := kernels.GetKernelVersion("", "/proc")
				fmt.Printf("failed object %s, kernel %s\n", fileName, kver)
			}
		}

		require.NoError(t, err, "failed to load resources into the kernel")

		collection.Close()
	}
}

// rewriteConfigConstants sets CONFIG_ITER_NUM as the production loader does
// (see rewriteConstants in pkg/sensors/program/loader_linux.go): the numeric
// iterator must be enabled on >=6.9 kernels, otherwise the fallback loop blows
// the 1M-instruction verifier limit.
func rewriteConfigConstants(spec *ebpf.CollectionSpec) error {
	v, ok := spec.Variables["CONFIG_ITER_NUM"]
	if !ok || !v.Constant() {
		return nil
	}

	enabled := bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9")
	return v.Set(enabled)
}

// programReferencesCelExpr reports whether prog calls any cel_expr function.
func programReferencesCelExpr(prog *ebpf.ProgramSpec) bool {
	for _, ins := range prog.Instructions {
		if strings.HasPrefix(ins.Reference(), "cel_expr") {
			return true
		}
	}
	return false
}

func isDebugEnabled() bool {
	debug, err := strconv.ParseBool(os.Getenv("DEBUG"))
	return err == nil && debug
}

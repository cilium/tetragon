// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/option"
)

// The cilium/ebpf library fails to load programs referencing ksyms when
// kallsyms addresses are restricted (kptr_restrict), even for weak ksyms,
// until we get https://github.com/cilium/ebpf/pull/2130.
//
// In such case (kptr_restrict set to 2) we set KSYMS_RESTRICTED rodata
// variable, so the bpf code referencing ksyms is skipped by verifier, and
// we replace the ksym references with zero value, so the library does not
// try to resolve them.
//
// TODO: remove once we have the cilium/ebpf fix.

const ksymsRestrictedVar = "KSYMS_RESTRICTED"

// Cache the decision so the shared, frozen rodata map and every
// subsequently loaded program use the same value.
var ksymsMissing = sync.OnceValue(func() bool {
	// Keep the conservative fallback when data symbols are omitted.
	all, err := kernels.DetectConfig(kernels.CONFIG_KALLSYMS_ALL)
	if err == nil && !all {
		return true
	}

	// arm64 reads the task's preempt count and s390 uses a weak kfunc.
	// Neither architecture requires an x86 preempt-count variable.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		return false
	}

	// Don't burden callers with errors here; a failure indicates a larger problem.
	file, err := os.Open(option.Config.ProcFS + "/kallsyms")
	if err != nil {
		return true
	}
	defer file.Close()

	// x86 kernels use either __preempt_count or pcpu_hot. Optional layout
	// markers are allowed to be absent, as in interrupt_context_level().
	s := bufio.NewScanner(file)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 3 && (fields[2] == "__preempt_count" || fields[2] == "pcpu_hot") {
			return false
		}
	}
	// An absent symbol or a failed scan both select the fallback.
	return true
})

// KsymsMissing reports whether context-helper symbols are missing from the
// running kernel's kallsyms. Inconclusive probes are treated as missing symbols.
func KsymsMissing() bool {
	return ksymsMissing()
}

// handleKsymsRestricted checks kptr_restrict for each sensor/program load,
// since the sysctl can change while Tetragon is running.
func handleKsymsRestricted(spec *ebpf.CollectionSpec) (bool, error) {
	v, ok := spec.Variables[ksymsRestrictedVar]
	// kptr_restrict is checked on each load, because it can change at any time.
	if !ok || !ksyms.KptrRestricted(option.Config.ProcFS) {
		return false, nil
	}
	if err := v.Set(uint8(1)); err != nil {
		return false, fmt.Errorf("rewriting constant %s: %w", ksymsRestrictedVar, err)
	}
	return true, nil
}

func handleKsyms(spec *ebpf.CollectionSpec) error {
	restricted, err := handleKsymsRestricted(spec)
	if err != nil {
		return err
	}
	if restricted || KsymsMissing() {
		stripKsymRefs(spec)
	}
	return nil
}

// Replaces all loads of ksym variables (ld_imm64 instructions referencing
// .ksyms BTF Var) with plain 'rX = 0' loads. The new instruction carries
// no ksym metadata, so the library does not try to resolve the symbol in
// kallsyms. Kfuncs (.ksyms BTF Func) are not touched.
func stripKsymRefs(spec *ebpf.CollectionSpec) {
	var ds *btf.Datasec

	if spec.Types == nil || spec.Types.TypeByName(".ksyms", &ds) != nil {
		return
	}

	names := map[string]struct{}{}
	for _, vsi := range ds.Vars {
		if v, ok := vsi.Type.(*btf.Var); ok {
			names[v.Name] = struct{}{}
		}
	}

	for _, prog := range spec.Programs {
		for i, ins := range prog.Instructions {
			if !ins.OpCode.IsDWordLoad() {
				continue
			}
			if _, ok := names[ins.Reference()]; !ok {
				continue
			}
			// Replace all ksym loads with zero value, all ksym vars are used
			// only when neither KSYMS_RESTRICTED nor KSYMS_MISSING is set,
			// so the zero value is never used.
			prog.Instructions[i] = asm.LoadImm(ins.Dst, 0, asm.DWord).
				WithSymbol(ins.Symbol()).
				WithSource(ins.Source())
		}
	}
}

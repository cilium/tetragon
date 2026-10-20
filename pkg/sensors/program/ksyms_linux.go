// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

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

func handleKsymsRestricted(spec *ebpf.CollectionSpec) error {
	v, ok := spec.Variables[ksymsRestrictedVar]
	// kptr_restrict is checked on each load, because it can change at any time.
	if !ok || !ksyms.KptrRestricted(option.Config.ProcFS) {
		return nil
	}
	if err := v.Set(uint8(1)); err != nil {
		return fmt.Errorf("rewriting constant %s: %w", ksymsRestrictedVar, err)
	}
	stripKsymRefs(spec)
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
			// only if KSYMS_RESTRICTED is not set, so the zero value is never
			// used.
			prog.Instructions[i] = asm.LoadImm(ins.Dst, 0, asm.DWord).
				WithSymbol(ins.Symbol()).
				WithSource(ins.Source())
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func UpdateStatsMap(m *ebpf.Map, val int64) error {
	if m.KeySize() != uint32(4) || m.ValueSize() != uint32(8) {
		return errors.New("wrong key/value size")
	}

	if m.Type() != ebpf.PerCPUArray {
		return errors.New("wrong map type")
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			// map fd into r1
			asm.LoadMapPtr(asm.R1, m.FD()),

			// 0 into &FP[-4]
			asm.LoadImm(asm.R2, 0, asm.DWord),
			asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

			// &FP[-4] into r2
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),

			asm.FnMapLookupElem.Call(),

			// NULL ptr, jump to error
			asm.JEq.Imm(asm.R0, 0, "error"),

			// add 'val' to the elem value
			asm.LoadImm(asm.R1, val, asm.DWord),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),

			// return 0
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),

			// return 1
			asm.LoadImm(asm.R0, 1, asm.DWord).WithSymbol("error"),
			asm.Return(),
		},
		License: "GPL",
	})

	if err != nil {
		return err
	}
	defer prog.Close()

	// not used, but needed to pass program test run
	in := make([]byte, 20)

	var ret uint32

	opts := ebpf.RunOptions{Data: in}
	ret, err = prog.Run(&opts)

	// executed, but failed in bpf program above
	if err == nil && ret != 0 {
		err = errors.New("failed to update map value")
	}
	return err
}

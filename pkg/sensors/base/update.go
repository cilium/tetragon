// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type execveMapUpdater struct {
	Load *program.Program
	Map  *program.Map
}

type UpdateData struct {
	pid uint32
	bit uint32
}

func (upd *execveMapUpdater) MBSetBitClear(bit uint32, pids []uint32) error {
	prog := upd.Load.Prog

	fmt.Printf("KRAVA MBSetBitClear ENTRY\n")

	// not used, but needed to pass program test run
	in := make([]byte, 20)

	opts := ebpf.RunOptions{Data: in}

	for _, pid := range pids {
		fmt.Printf("pid %d bit %d\n", pid, bit)

		key := uint32(0)
		val := UpdateData{pid, bit}

		if err := upd.Map.MapHandle.Update(key, val, 0); err != nil {
			fmt.Printf("KRAVA MBSetBitClear update %v\n", err)
			return errors.New("failed to update data map value")
		}

		ret, err := prog.Run(&opts)

		fmt.Printf("KRAVA MBSetBitClear run %v\n", err)
		// executed, but failed in bpf program above
		if err == nil && ret != 0 {
			return errors.New("failed to update map value")
		}
	}

	fmt.Printf("KRAVA MBSetBitClear EXIT\n")
	return nil
}

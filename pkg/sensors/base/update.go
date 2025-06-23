// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	maxPids = 32768
)

type execveMapUpdater struct {
	Load *program.Program
	Map  *program.Map
}

type UpdateData struct {
	bit  uint32
	cnt  uint32
	pids [maxPids]uint32
}

func getRoundCnt() uint32 {
	if config.EnableV61Progs() {
		return maxPids
	} else if kernels.MinKernelVersion("5.11") {
		return 1024
	} else if config.EnableLargeProgs() {
		return 1024
	}
	return 0
}

func (upd *execveMapUpdater) MBSetBitClear(bit uint32, pids []uint32) error {
	prog := upd.Load.Prog

	// not used, but needed to pass program test run
	in := make([]byte, 20)

	opts := ebpf.RunOptions{Data: in}

	key := uint32(0)
	val := UpdateData{
		bit: bit,
	}

	run := func() error {
		if err := upd.Map.MapHandle.Update(key, val, 0); err != nil {
			return errors.New("failed to update data map value")
		}

		ret, err := prog.Run(&opts)

		// executed, but failed in bpf program above
		if err != nil || ret != 0 {
			return errors.New("failed to update map value")
		}
		return nil
	}

	var err error

	maxCnt := getRoundCnt()

	for _, pid := range pids {
		if val.cnt < maxCnt {
			val.pids[val.cnt] = pid
			val.cnt++
			continue
		}

		// update every maxCnt keys
		if err := run(); err != nil {
			return err
		}
		val.cnt = 0
	}

	// ... and the rest
	if val.cnt > 0 {
		err = run()
	}

	return err
}

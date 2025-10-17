// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Implementation freely taken by https://github.com/iovisor/bcc/blob/b63d7e38e8a0f6339fbd57f3a1ae7297e1993d92/src/cc/usdt/usdt_args.cc#L224
// and arranged to be similar to usdt_args_amd64 one.

//go:build arm64 && linux
// +build arm64,linux

package elf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const closingRune = ']'

var (
	ptregs unix.PtraceRegs
	// Parsers sorting IS important!
	parsers = []fn{
		parseConst,    // <size>@<value>
		parseRegDeref, // <size>@[<reg>] and <size>@[<reg,<offset>]
		parseSIB,      //  <size>@[<reg>,<index_reg>]
		parseReg,      // <size>@<reg>
	}
)

func resolveReg(name string) (uint16, bool) {
	if name == "sp" {
		return uint16(unsafe.Offsetof(ptregs.Sp)), true
	}
	var idx int
	_, err := fmt.Sscanf(name, "x%d", &idx)
	if err == nil && idx >= 0 && idx <= 31 {
		if idx == 31 {
			return resolveReg("sp")
		}
		baseOff := unsafe.Offsetof(ptregs.Regs)
		shift := unsafe.Sizeof(ptregs.Regs[0]) * uintptr(idx)
		return uint16(baseOff + shift), true
	}
	return 0, false
}

// Parse <size>@[<reg>,<index_reg>]
func parseSIB(str string, arg *UsdtArg) error {
	var (
		sz     int
		off    int64
		reg    RegScanner
		regIdx RegScanner
		n      int
		ok     bool
	)

	// <size>@[<reg>,<index_reg>]
	if n, _ = fmt.Sscanf(str, "%d@[%s,%s]", &sz, &reg, &regIdx); n != 3 {
		return errNext
	}

	arg.Type = USDT_ARG_TYPE_SIB
	arg.ValOff = uint64(off)
	arg.RegOff, ok = resolveReg(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	arg.RegIdxOff, ok = resolveReg(regIdx.name)
	if !ok {
		return fmt.Errorf("failed to parse index register '%s'", regIdx.name)
	}

	return parseCommon(sz, arg)
}

// Parse <size>@[<reg>] and <size>@[<reg,<offset>]
func parseRegDeref(str string, arg *UsdtArg) error {
	var (
		sz  int
		off int64
		reg RegScanner
		n   int
		ok  bool
	)

	// <size>@[<reg,<offset>]
	if n, _ = fmt.Sscanf(str, "%d@[%s,%d]", &sz, reg.Reset(), &off); n != 3 {
		// <size>@[<reg>]
		if n, _ = fmt.Sscanf(str, "%d@[%s]", &sz, reg.Reset()); n != 2 {
			return errNext
		}
	}

	arg.Type = USDT_ARG_TYPE_REG_DEREF
	arg.ValOff = uint64(off)
	arg.RegOff, ok = resolveReg(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	return parseCommon(sz, arg)
}

// Parse <size>@<reg>
func parseReg(str string, arg *UsdtArg) error {
	var (
		sz  int
		reg RegScanner
		n   int
		ok  bool
	)

	if n, _ = fmt.Sscanf(str, "%d@%s", &sz, &reg); n != 2 {
		return errNext
	}

	arg.Type = USDT_ARG_TYPE_REG
	arg.ValOff = 0
	arg.RegOff, ok = resolveReg(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	return parseCommon(sz, arg)
}

// Parse <size>@<value>
func parseConst(str string, arg *UsdtArg) error {
	var (
		sz  int
		n   int
		off int
	)

	if n, _ = fmt.Sscanf(str, "%d@%d", &sz, &off); n != 2 {
		return errNext
	}

	arg.Type = USDT_ARG_TYPE_CONST
	arg.ValOff = uint64(off)
	arg.RegOff = 0

	return parseCommon(sz, arg)
}

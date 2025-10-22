// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package elf

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/asm"
)

const closingRune = ')'

var (
	parsers = []fn{
		parseSIB,
		parseRegDeref,
		parseReg,
		parseConst,
	}
)

func parseSIB(str string, arg *UsdtArg) error {
	var (
		sz     int
		off    int64
		reg    RegScanner
		regIdx RegScanner
		n      int
		ok     bool
		scale  = 1
	)

	// 1@-96(%rbp,%rax,8)
	if n, _ = fmt.Sscanf(str, "%d@%d(%%%s,%%%s,%d)", &sz, &off, &reg, &regIdx, &scale); n != 5 {
		// 1@(%rbp,%rax,8)
		if n, _ = fmt.Sscanf(str, "%d@(%%%s,%%%s,%d)", &sz, reg.Reset(), regIdx.Reset(), &scale); n != 4 {
			// 1@-96(%rbp,%rax)
			if n, _ = fmt.Sscanf(str, "%d@%d(%%%s,%%%s)", &sz, &off, reg.Reset(), regIdx.Reset()); n != 4 {
				// 1@(%rbp,%rax)
				if n, _ = fmt.Sscanf(str, "%d@(%%%s,%%%s)", &sz, reg.Reset(), regIdx.Reset()); n != 3 {
					return errNext
				}
			}
		}
	}

	arg.Type = USDT_ARG_TYPE_SIB
	arg.ValOff = uint64(off)
	arg.RegOff, ok = asm.RegOffset(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	arg.RegIdxOff, ok = asm.RegOffset(regIdx.name)
	if !ok {
		return fmt.Errorf("failed to parse index register '%s'", regIdx.name)
	}

	switch scale {
	case 1:
		arg.Scale = 0
	case 2:
		arg.Scale = 1
	case 4:
		arg.Scale = 2
	case 8:
		arg.Scale = 3
	}

	return parseCommon(sz, arg)
}

func parseRegDeref(str string, arg *UsdtArg) error {
	var (
		sz  int
		off int64
		reg RegScanner
		n   int
		ok  bool
	)

	if n, _ = fmt.Sscanf(str, "%d@%d(%%%s)", &sz, &off, &reg); n != 3 {
		if n, _ = fmt.Sscanf(str, "%d@(%%%s)", &sz, &reg); n != 2 {
			return errNext
		}
	}

	arg.Type = USDT_ARG_TYPE_REG_DEREF
	arg.ValOff = uint64(off)
	arg.RegOff, ok = asm.RegOffset(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	return parseCommon(sz, arg)
}

func parseReg(str string, arg *UsdtArg) error {
	var (
		sz  int
		reg RegScanner
		n   int
		ok  bool
	)

	if n, _ = fmt.Sscanf(str, "%d@%%%s", &sz, &reg); n != 2 {
		return errNext
	}

	arg.Type = USDT_ARG_TYPE_REG
	arg.ValOff = 0
	arg.RegOff, ok = asm.RegOffset(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	return parseCommon(sz, arg)
}

func parseConst(str string, arg *UsdtArg) error {
	var (
		sz  int
		n   int
		off int
	)

	if n, _ = fmt.Sscanf(str, "%d@$%d", &sz, &off); n != 2 {
		return errNext
	}

	arg.Type = USDT_ARG_TYPE_CONST
	arg.ValOff = uint64(off)
	arg.RegOff = 0

	return parseCommon(sz, arg)
}

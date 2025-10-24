// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Implementation freely taken by https://github.com/iovisor/bcc/blob/b63d7e38e8a0f6339fbd57f3a1ae7297e1993d92/src/cc/usdt/usdt_args.cc#L224
// and arranged to be similar to usdtargs_linux_amd64 one.

package elf

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/asm"
)

const closingRune = ']'

var (
	parsers = []fn{
		parseConst,       // <size>@<value>
		parseRegDerefSIB, // <size>@[<reg>], <size>@[<reg>,<index_reg>] and <size>@[<reg,<offset>]
		parseReg,         // <size>@<reg>
	}
)

// Parse <size>@[<reg>], <size>@[<reg>,<index_reg>], <size>@[<reg,<offset>]
// We need a single parser because <size>@[<reg>] (matched by %d@[%s]) has a larger match
// that would also match SIB one: %d@[%s,%s].
// At the same time, if we try to parse string as SIB first, %d@[%s,%s] would
// steal the possible match of %d@[%s,%d] (<size>@[<reg,<offset>]).
func parseRegDerefSIB(str string, arg *UsdtArg) error {
	var (
		sz     int
		off    int64
		reg    RegScanner
		regIdx RegScanner
		n      int
		ok     bool
	)

	argType := USDT_ARG_TYPE_REG_DEREF

	// <size>@[<reg,<offset>]
	if n, _ = fmt.Sscanf(str, "%d@[%s,%d]", &sz, reg.Reset(), &off); n != 3 {
		// <size>@[<reg>,<index_reg>]
		if n, _ = fmt.Sscanf(str, "%d@[%s,%s]", &sz, reg.Reset(), &regIdx); n != 3 {
			// <size>@[<reg>]
			if n, _ = fmt.Sscanf(str, "%d@[%s]", &sz, reg.Reset()); n != 2 {
				return errNext
			}
		} else {
			argType = USDT_ARG_TYPE_SIB
		}
	}

	arg.Type = argType
	arg.ValOff = uint64(off)
	arg.RegOff, ok = asm.RegOffset(reg.name)
	if !ok {
		return fmt.Errorf("failed to parse register '%s'", reg.name)
	}

	if argType == USDT_ARG_TYPE_SIB {
		arg.RegIdxOff, ok = asm.RegOffset(regIdx.name)
		if !ok {
			return fmt.Errorf("failed to parse index register '%s'", regIdx.name)
		}
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
	arg.RegOff, ok = asm.RegOffset(reg.name)
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

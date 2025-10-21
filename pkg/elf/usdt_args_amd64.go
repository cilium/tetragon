// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package elf

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/tetragon/pkg/asm"
)

var errNext = errors.New("next")

type fn func(str string, arg *UsdtArg) error

type RegScanner struct {
	name string
}

func (sc *RegScanner) Reset() *RegScanner {
	sc.name = ""
	return sc
}

func (sc *RegScanner) Scan(state fmt.ScanState, _ rune) error {

	for {
		r, _, err := state.ReadRune()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if r == ',' || r == ' ' || r == ')' {
			state.UnreadRune()
			break
		}
		sc.name = sc.name + string(r)
	}
	return nil
}

func parseCommon(sz int, arg *UsdtArg) error {
	arg.Signed = sz < 0
	if sz < 0 {
		sz = -sz
	}
	arg.Size = sz

	switch sz {
	case 1, 2, 4, 8:
		arg.Shift = 64 - uint8(sz)*8
	default:
		return fmt.Errorf("wrong sz %d", sz)
	}
	return nil
}

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

func parseArgs(spec *UsdtSpec) error {

	parsers := []fn{
		parseSIB,
		parseRegDeref,
		parseReg,
		parseConst,
	}

	for idx, str := range strings.Split(spec.ArgsStr, " ") {
		arg := &spec.Args[idx]

		for _, parse := range parsers {
			err := parse(str, arg)
			if err == nil {
				break
			}
			if !errors.Is(err, errNext) {
				return err
			}
		}
		arg.Str = str
		spec.ArgsCnt++
	}

	return nil
}

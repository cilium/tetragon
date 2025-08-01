// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package elf

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type reg struct {
	name [4]string
	off  uint16
}

var ptregs unix.PtraceRegs

var regs = []reg{
	reg{[4]string{"rip", "eip", "", ""}, uint16(unsafe.Offsetof(ptregs.Rip))},
	reg{[4]string{"rax", "eax", "ax", "al"}, uint16(unsafe.Offsetof(ptregs.Rax))},
	reg{[4]string{"rbx", "ebx", "bx", "bl"}, uint16(unsafe.Offsetof(ptregs.Rbx))},
	reg{[4]string{"rcx", "ecx", "cx", "cl"}, uint16(unsafe.Offsetof(ptregs.Rcx))},
	reg{[4]string{"rdx", "edx", "dx", "dl"}, uint16(unsafe.Offsetof(ptregs.Rdx))},
	reg{[4]string{"rsi", "esi", "si", "sil"}, uint16(unsafe.Offsetof(ptregs.Rsi))},
	reg{[4]string{"rdi", "edi", "di", "dil"}, uint16(unsafe.Offsetof(ptregs.Rdi))},
	reg{[4]string{"rbp", "ebp", "bp", "bpl"}, uint16(unsafe.Offsetof(ptregs.Rbp))},
	reg{[4]string{"rsp", "esp", "sp", "spl"}, uint16(unsafe.Offsetof(ptregs.Rsp))},
	reg{[4]string{"r8", "r8d", "r8w", "r8b"}, uint16(unsafe.Offsetof(ptregs.R8))},
	reg{[4]string{"r9", "r9d", "r9w", "r9b"}, uint16(unsafe.Offsetof(ptregs.R9))},
	reg{[4]string{"r10", "r10d", "r10w", "r10b"}, uint16(unsafe.Offsetof(ptregs.R10))},
	reg{[4]string{"r11", "r11d", "r11w", "r11b"}, uint16(unsafe.Offsetof(ptregs.R11))},
	reg{[4]string{"r12", "r12d", "r12w", "r12b"}, uint16(unsafe.Offsetof(ptregs.R12))},
	reg{[4]string{"r13", "r13d", "r13w", "r13b"}, uint16(unsafe.Offsetof(ptregs.R13))},
	reg{[4]string{"r14", "r14d", "r14w", "r14b"}, uint16(unsafe.Offsetof(ptregs.R14))},
	reg{[4]string{"r15", "r15d", "r15w", "r15b"}, uint16(unsafe.Offsetof(ptregs.R15))},
}

func resolveReg(name string) (uint16, bool) {
	for _, reg := range regs {
		for _, n := range reg.name {
			if n == name {
				return reg.off, true
			}
		}
	}
	return 0, false
}

func parseArgs(spec *UsdtSpec) error {
	for idx, str := range strings.Split(spec.ArgsStr, " ") {
		var (
			arg = &spec.Args[idx]
			sz  int
			off int64
			reg string
			n   int
			ok  bool
		)

		cut := func(r string) string { return r[:len(r)-1] }

		if n, _ = fmt.Sscanf(str, "%d@%d(%%%s)", &sz, &off, &reg); n == 3 {
			arg.Type = USDT_ARG_TYPE_REG_DEREF
			arg.ValOff = uint64(off)
			arg.RegOff, ok = resolveReg(cut(reg))
			if !ok {
				return fmt.Errorf("failed to parse register '%s'", reg)
			}
		} else if n, _ = fmt.Sscanf(str, "%d@(%%%s)", &sz, &reg); n == 2 {
			arg.Type = USDT_ARG_TYPE_REG_DEREF
			arg.ValOff = 0
			arg.RegOff, ok = resolveReg(cut(reg))
			if !ok {
				return fmt.Errorf("failed to parse register '%s'", reg)
			}
		} else if n, _ = fmt.Sscanf(str, "%d@%%%s", &sz, &reg); n == 2 {
			arg.Type = USDT_ARG_TYPE_REG
			arg.ValOff = 0
			arg.RegOff, ok = resolveReg(reg)
			if !ok {
				return fmt.Errorf("failed to parse register '%s'", reg)
			}
		} else if n, _ = fmt.Sscanf(str, "%d@$%d", &sz, &off); n == 2 {
			arg.Type = USDT_ARG_TYPE_CONST
			arg.ValOff = uint64(off)
			arg.RegOff = 0
		} else {
			return fmt.Errorf("failed to parse argument '%s'", str)
		}

		arg.Signed = sz < 0
		if sz < 0 {
			sz = -sz
		}
		arg.Size = sz

		switch sz {
		case 1, 2, 4, 8:
			arg.Shift = 64 - uint8(sz)*8
		}

		arg.Str = str
		spec.ArgsCnt++
	}

	return nil
}

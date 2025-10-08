// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package asm

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type offset struct {
	name [4]string
	val  uint16
}

var ptregs unix.PtraceRegs

var offsets = []offset{
	offset{[4]string{"rip", "eip", "", ""}, uint16(unsafe.Offsetof(ptregs.Rip))},
	offset{[4]string{"rax", "eax", "ax", "al"}, uint16(unsafe.Offsetof(ptregs.Rax))},
	offset{[4]string{"rbx", "ebx", "bx", "bl"}, uint16(unsafe.Offsetof(ptregs.Rbx))},
	offset{[4]string{"rcx", "ecx", "cx", "cl"}, uint16(unsafe.Offsetof(ptregs.Rcx))},
	offset{[4]string{"rdx", "edx", "dx", "dl"}, uint16(unsafe.Offsetof(ptregs.Rdx))},
	offset{[4]string{"rsi", "esi", "si", "sil"}, uint16(unsafe.Offsetof(ptregs.Rsi))},
	offset{[4]string{"rdi", "edi", "di", "dil"}, uint16(unsafe.Offsetof(ptregs.Rdi))},
	offset{[4]string{"rbp", "ebp", "bp", "bpl"}, uint16(unsafe.Offsetof(ptregs.Rbp))},
	offset{[4]string{"rsp", "esp", "sp", "spl"}, uint16(unsafe.Offsetof(ptregs.Rsp))},
	offset{[4]string{"r8", "r8d", "r8w", "r8b"}, uint16(unsafe.Offsetof(ptregs.R8))},
	offset{[4]string{"r9", "r9d", "r9w", "r9b"}, uint16(unsafe.Offsetof(ptregs.R9))},
	offset{[4]string{"r10", "r10d", "r10w", "r10b"}, uint16(unsafe.Offsetof(ptregs.R10))},
	offset{[4]string{"r11", "r11d", "r11w", "r11b"}, uint16(unsafe.Offsetof(ptregs.R11))},
	offset{[4]string{"r12", "r12d", "r12w", "r12b"}, uint16(unsafe.Offsetof(ptregs.R12))},
	offset{[4]string{"r13", "r13d", "r13w", "r13b"}, uint16(unsafe.Offsetof(ptregs.R13))},
	offset{[4]string{"r14", "r14d", "r14w", "r14b"}, uint16(unsafe.Offsetof(ptregs.R14))},
	offset{[4]string{"r15", "r15d", "r15w", "r15b"}, uint16(unsafe.Offsetof(ptregs.R15))},
}

func RegOffset(name string) (uint16, bool) {
	for _, off := range offsets {
		for _, n := range off.name {
			if n == name {
				return off.val, true
			}
		}
	}
	return 0, false
}

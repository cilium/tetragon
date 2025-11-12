// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"github.com/cilium/ebpf/asm"
)

type codeGenerator struct {
	insts    asm.Instructions
	stackTop int16
}

func newCodeGenerator() *codeGenerator {
	return &codeGenerator{
		insts: asm.Instructions{},
	}
}

func (g *codeGenerator) instructions() asm.Instructions {
	return g.insts
}

func (g *codeGenerator) emitRaw(insts ...asm.Instruction) {
	g.insts = append(g.insts, insts...)
}

func (g *codeGenerator) emitPushBool(val bool) {
	imm := int32(0)
	if val {
		imm = 1
	}
	g.stackTop -= 8
	g.emitRaw(
		asm.Mov.Imm(asm.R3, imm),
		asm.StoreMem(asm.R10, g.stackTop, asm.R3, asm.DWord),
	)
}

func (g *codeGenerator) emitPopBool(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

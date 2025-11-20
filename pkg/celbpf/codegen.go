// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

var scratchRegs = []asm.Register{asm.R1, asm.R2, asm.R3, asm.R4, asm.R5}

type codeGenerator struct {
	insts       asm.Instructions
	stackTop    int16
	labelPrefix string
	labelID     uint
}

func (g *codeGenerator) generateLabel() string {
	ret := fmt.Sprintf("%s_l%03d", g.labelPrefix, g.labelID)
	g.labelID++
	return ret
}

func newCodeGenerator(labelPrefix string) *codeGenerator {
	return &codeGenerator{
		insts:       asm.Instructions{},
		labelPrefix: labelPrefix,
	}
}

func (g *codeGenerator) instructions() asm.Instructions {
	return g.insts
}

func (g *codeGenerator) emitRaw(insts ...asm.Instruction) {
	g.insts = append(g.insts, insts...)
}

func (g *codeGenerator) emitPushBool(val bool, tmp asm.Register) {
	imm := int32(0)
	if val {
		imm = 1
	}
	g.stackTop -= 8
	g.emitRaw(
		asm.Mov.Imm(tmp, imm),
		asm.StoreMem(asm.R10, g.stackTop, tmp, asm.DWord),
	)
}

func (g *codeGenerator) emitPopBool(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitPushInt64(val int64, tmp asm.Register) {
	g.stackTop -= 8
	g.emitRaw(
		asm.LoadImm(tmp, val, asm.DWord),
		asm.StoreMem(asm.R10, g.stackTop, tmp, asm.DWord),
	)
}

func (g *codeGenerator) emitPopInt64(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitBranchEquals(reg0 asm.Register, reg1 asm.Register) {
	// make space to push a boolean (8 bytes)
	g.stackTop -= 8
	label := g.generateLabel()
	g.emitRaw(
		// check reg0 vs reg1, and then use reg0 for the result so that we can save it in
		// the stack.
		asm.JEq.Reg(reg0, reg1, label),
		asm.LoadImm(reg0, 0, asm.DWord),
		asm.Instruction{OpCode: asm.Ja.Op(asm.ImmSource), Offset: 2},
		asm.LoadImm(reg0, 1, asm.DWord).WithSymbol(label),
		asm.StoreMem(asm.R10, g.stackTop, reg0, asm.DWord),
	)

}

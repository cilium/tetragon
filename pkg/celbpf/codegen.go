// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	cgTypes "github.com/google/cel-go/common/types"
)

var scratchRegs = []asm.Register{asm.R3, asm.R4, asm.R5}

var argArgsOff = asm.R1 // first argument
var argArgs = asm.R2    // second argument

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

func (g *codeGenerator) emitPushBool(val bool) {
	imm := int32(0)
	if val {
		imm = 1
	}
	g.stackTop -= 8
	g.emitRaw(
		asm.Mov.Imm(scratchRegs[0], imm),
		asm.StoreMem(asm.R10, g.stackTop, scratchRegs[0], asm.DWord),
	)
}

func (g *codeGenerator) emitPopBool(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitPushInt64(val int64) {
	g.stackTop -= 8
	g.emitRaw(
		asm.LoadImm(asm.R3, val, asm.DWord),
		asm.StoreMem(asm.R10, g.stackTop, asm.R3, asm.DWord),
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
		asm.JEq.Reg(reg0, reg1, label),
		asm.LoadImm(asm.R3, 0, asm.DWord),
		asm.Instruction{OpCode: asm.Ja.Op(asm.ImmSource), Offset: 2},
		asm.LoadImm(asm.R3, 1, asm.DWord).WithSymbol(label),
		asm.StoreMem(asm.R10, g.stackTop, asm.R3, asm.DWord),
	)

}

func (g *codeGenerator) emitPopS32(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitS32(reg asm.Register, regTy *cgTypes.Type) error {
	switch regTy {
	case s64Ty:
		g.emitRaw(
			asm.LSh.Imm(reg, 0x20),
			asm.ArSh.Imm(reg, 0x20),
		)
	default:
		return fmt.Errorf("emitS32: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitPopU32(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitU32(reg asm.Register, regTy *cgTypes.Type) error {

	switch regTy {
	case u64Ty:
		g.emitRaw(
			asm.LSh.Imm(reg, 0x20),
			asm.RSh.Imm(reg, 0x20),
		)
	default:
		return fmt.Errorf("emitU32: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) pushArg(argTy *cgTypes.Type, argOffset int) error {
	switch argTy {
	case u32Ty, s32Ty:
		g.stackTop -= 8
		g.emitRaw(
			// r3 = *(u64 *)(argArgsOff + idx)
			asm.LoadMem(asm.R3, argArgsOff, int16(argOffset*8), asm.DWord),
			asm.And.Imm(asm.R3, 0x7ff),
			// r3 += args
			asm.Add.Reg(asm.R3, argArgs),
			// r4 = *(u32 *)(r3)
			asm.LoadMem(asm.R4, asm.R3, 0, asm.Word),
			asm.StoreMem(asm.R10, g.stackTop, asm.R4, asm.DWord),
		)
	case u64Ty, s64Ty:
		g.stackTop -= 8
		g.emitRaw(
			// r3 = *(u64 *)(argArgsOff + idx)
			asm.LoadMem(asm.R3, argArgsOff, int16(argOffset*8), asm.DWord),
			asm.And.Imm(asm.R3, 0x7ff),
			// r3 += args
			asm.Add.Reg(asm.R3, argArgs),
			// r4 = *(u64 *)(r3)
			asm.LoadMem(asm.R4, asm.R3, 0, asm.DWord),
			asm.StoreMem(asm.R10, g.stackTop, asm.R4, asm.DWord),
		)
	default:
		return fmt.Errorf("unsupported type: %s", argTy.TypeName())
	}

	return nil
}

// emit subtraction
func (g *codeGenerator) emitSub(
	r1 asm.Register, ty1 *cgTypes.Type,
	r2 asm.Register, ty2 *cgTypes.Type,
) error {
	switch {
	case ty1.TypeName() == s64Ty.TypeName() && ty2.TypeName() == s64Ty.TypeName(),
		ty1.TypeName() == s32Ty.TypeName() && ty2.TypeName() == s32Ty.TypeName(),
		ty1.TypeName() == u64Ty.TypeName() && ty2.TypeName() == u64Ty.TypeName(),
		ty1.TypeName() == u32Ty.TypeName() && ty2.TypeName() == u32Ty.TypeName():

		g.stackTop -= 8
		g.emitRaw(
			asm.Sub.Reg(r1, r2),
			asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord),
		)

	default:
		return fmt.Errorf("subtraction between types %s and %s is not supported", ty1.TypeName(), ty2.TypeName())
	}

	return nil
}

// emit addition
func (g *codeGenerator) emitAdd(
	r1 asm.Register, ty1 *cgTypes.Type,
	r2 asm.Register, ty2 *cgTypes.Type,
) error {
	switch {
	case ty1.TypeName() == s64Ty.TypeName() && ty2.TypeName() == s64Ty.TypeName(),
		ty1.TypeName() == s32Ty.TypeName() && ty2.TypeName() == s32Ty.TypeName(),
		ty1.TypeName() == u64Ty.TypeName() && ty2.TypeName() == u64Ty.TypeName(),
		ty1.TypeName() == u32Ty.TypeName() && ty2.TypeName() == u32Ty.TypeName():

		g.stackTop -= 8
		g.emitRaw(
			asm.Add.Reg(r1, r2),
			asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord),
		)

	default:
		return fmt.Errorf("addition between types %s and %s is not supported", ty1.TypeName(), ty2.TypeName())
	}

	return nil
}

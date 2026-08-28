// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf/asm"
	cgOperators "github.com/google/cel-go/common/operators"
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

// emitPushInt64 pushes the 64-bit register onto the stack.
// This is used for all values, even ones with smaller widths,
// to keep the stack aligned to 8 bytes for simplicity.
func (g *codeGenerator) emitPushInt64(val int64, tmp asm.Register) {
	g.stackTop -= 8
	g.emitRaw(
		asm.LoadImm(tmp, val, asm.DWord),
		asm.StoreMem(asm.R10, g.stackTop, tmp, asm.DWord),
	)
}

// emitPopInt64 pops the 64-bit register from the stack.
// This is used for all values, even ones with smaller widths,
// to keep the stack aligned to 8 bytes for simplicity.
func (g *codeGenerator) emitPopInt64(reg asm.Register) {
	g.emitRaw(asm.LoadMem(reg, asm.R10, g.stackTop, asm.DWord))
	g.stackTop += 8
}

func (g *codeGenerator) emitS32(reg asm.Register, regTy *cgTypes.Type) error {
	switch regTy {
	case s64Ty:
	default:
		return fmt.Errorf("emitS32: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitU32(reg asm.Register, regTy *cgTypes.Type) error {

	switch regTy {
	case u64Ty:
	default:
		return fmt.Errorf("emitU32: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitS16(reg asm.Register, regTy *cgTypes.Type) error {
	switch regTy {
	case s64Ty:
	default:
		return fmt.Errorf("emitS16: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.LSh.Imm(reg, 48),
		asm.ArSh.Imm(reg, 48),
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitU16(reg asm.Register, regTy *cgTypes.Type) error {

	switch regTy {
	case u64Ty:
	default:
		return fmt.Errorf("emitU16: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.And.Imm(reg, 0xffff),
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitS8(reg asm.Register, regTy *cgTypes.Type) error {
	switch regTy {
	case s64Ty:
	default:
		return fmt.Errorf("emitS8: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.LSh.Imm(reg, 56),
		asm.ArSh.Imm(reg, 56),
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) emitU8(reg asm.Register, regTy *cgTypes.Type) error {

	switch regTy {
	case u64Ty:
	default:
		return fmt.Errorf("emitU8: unknown/unsupported type %s", regTy)
	}

	g.stackTop -= 8
	g.emitRaw(
		asm.And.Imm(reg, 0xff),
		asm.StoreMem(asm.R10, g.stackTop, reg, asm.DWord),
	)
	return nil
}

func (g *codeGenerator) pushArg(argTy *cgTypes.Type, argOffset uint16, tmp1, tmp2 asm.Register) error {
	off := int(argOffset * 8)
	if off > math.MaxInt16 {
		return fmt.Errorf("offset %d overflows 16-bits", off)
	}
	off16 := int16(off)

	// Load the offset of the argument from argArgsOff into tmp1,
	// and add it to argArgs to get the address of the argument.
	g.emitRaw(
		// tmp1 = *(u64 *)(argArgsOff + idx)
		asm.LoadMem(tmp1, argArgsOff, off16, asm.DWord),
		asm.And.Imm(tmp1, 0x7ff),
		// tmp1 += args
		asm.Add.Reg(tmp1, argArgs),
	)

	// Load the argument with the correct width into a register
	switch argTy {
	case u8Ty:
		g.emitRaw(
			// tmp2 = *(u8 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.Byte),
		)
	case s8Ty:
		g.emitRaw(
			// tmp2 = *(s8 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.Byte),
			asm.LSh.Imm(tmp2, 56),
			asm.ArSh.Imm(tmp2, 56),
		)
	case u16Ty:
		g.emitRaw(
			// tmp2 = *(u16 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.Half),
		)
	case s16Ty:
		g.emitRaw(
			// tmp2 = *(s16 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.Half),
			asm.LSh.Imm(tmp2, 48),
			asm.ArSh.Imm(tmp2, 48),
		)
	case u32Ty, s32Ty:
		g.emitRaw(
			// tmp2 = *(u32 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.Word),
		)
	case u64Ty, s64Ty:
		g.emitRaw(
			// tmp2 = *(u64 *)(tmp1)
			asm.LoadMem(tmp2, tmp1, 0, asm.DWord),
		)
	default:
		return fmt.Errorf("unsupported type: %s", argTy.TypeName())
	}

	// Push the loaded argument onto the stack as a 64-bit value.
	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, tmp2, asm.DWord),
	)

	return nil
}

// emit subtraction
func (g *codeGenerator) emitArithOp(
	op asm.ALUOp,
	r1 asm.Register, ty1 *cgTypes.Type,
	r2 asm.Register, ty2 *cgTypes.Type,
) error {
	var ins asm.Instruction
	switch {
	case ty1.TypeName() == s64Ty.TypeName() && ty2.TypeName() == s64Ty.TypeName(),
		ty1.TypeName() == u64Ty.TypeName() && ty2.TypeName() == u64Ty.TypeName():
		ins = op.Reg(r1, r2)

	case ty1.TypeName() == s32Ty.TypeName() && ty2.TypeName() == s32Ty.TypeName(),
		ty1.TypeName() == u32Ty.TypeName() && ty2.TypeName() == u32Ty.TypeName(),
		ty1.TypeName() == s16Ty.TypeName() && ty2.TypeName() == s16Ty.TypeName(),
		ty1.TypeName() == u16Ty.TypeName() && ty2.TypeName() == u16Ty.TypeName(),
		ty1.TypeName() == s8Ty.TypeName() && ty2.TypeName() == s8Ty.TypeName(),
		ty1.TypeName() == u8Ty.TypeName() && ty2.TypeName() == u8Ty.TypeName():
		ins = op.Reg32(r1, r2)

	default:
		return fmt.Errorf("operation between types %s and %s is not supported %T %T", ty1.TypeName(), ty2.TypeName(), ty1, ty2)
	}

	if ins.OpCode == asm.InvalidOpCode {
		return fmt.Errorf("invalid opcode for ALU op %v", op)
	}

	// Emit arithmetic instructions, the result is in r1.
	g.emitRaw(ins)

	// Convert the value to a lower width type if needed.
	switch {
	case ty1.TypeName() == u16Ty.TypeName() && ty2.TypeName() == u16Ty.TypeName():
		g.emitRaw(
			asm.And.Imm(r1, 0xffff),
		)
	case ty1.TypeName() == s16Ty.TypeName() && ty2.TypeName() == s16Ty.TypeName():
		g.emitRaw(
			asm.LSh.Imm(r1, 48),
			asm.ArSh.Imm(r1, 48),
		)
	case ty1.TypeName() == u8Ty.TypeName() && ty2.TypeName() == u8Ty.TypeName():
		g.emitRaw(
			asm.And.Imm(r1, 0xff),
		)
	case ty1.TypeName() == s8Ty.TypeName() && ty2.TypeName() == s8Ty.TypeName():
		g.emitRaw(
			asm.LSh.Imm(r1, 56),
			asm.ArSh.Imm(r1, 56),
		)
	}

	// Finally store the result on the stack.
	g.stackTop -= 8
	g.emitRaw(
		asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord),
	)

	return nil
}

// emit AND
func (g *codeGenerator) emitAND(r1 asm.Register, r2 asm.Register) error {
	g.stackTop -= 8
	g.emitRaw(
		asm.And.Reg(r1, r2),
		asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord),
	)
	return nil
}

// emit OR
func (g *codeGenerator) emitOR(r1 asm.Register, r2 asm.Register) error {
	g.stackTop -= 8
	g.emitRaw(
		asm.Or.Reg(r1, r2),
		asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord),
	)
	return nil
}

// emit Not
func (g *codeGenerator) emitNot(r1 asm.Register, tmp asm.Register) error {
	g.stackTop -= 8
	label := g.generateLabel()
	g.emitRaw(
		asm.LoadImm(tmp, 1, asm.DWord),
		asm.JEq.Imm(r1, 0, label),
		asm.LoadImm(tmp, 0, asm.DWord),
		asm.StoreMem(asm.R10, g.stackTop, tmp, asm.DWord).WithSymbol(label),
	)
	return nil
}

func (g *codeGenerator) emitBitwiseNot(
	r1 asm.Register, ty1 *cgTypes.Type,
) error {
	var ins asm.Instruction
	switch ty1.TypeName() {
	case s64Ty.TypeName(), u64Ty.TypeName():
		ins = asm.Xor.Imm(r1, -1)
	case s32Ty.TypeName(), u32Ty.TypeName():
		ins = asm.Xor.Imm32(r1, -1)
	case s16Ty.TypeName(), u16Ty.TypeName():
		ins = asm.Xor.Imm32(r1, 0xffff)
	case s8Ty.TypeName(), u8Ty.TypeName():
		ins = asm.Xor.Imm32(r1, 0xff)
	default:
		return fmt.Errorf("bitwise NOT on type %s is not supported", ty1.TypeName())
	}

	g.stackTop -= 8
	g.emitRaw(ins)
	switch ty1.TypeName() {
	case u8Ty.TypeName():
		g.emitRaw(asm.And.Imm(r1, 0xff))
	case u16Ty.TypeName():
		g.emitRaw(asm.And.Imm(r1, 0xffff))
	case s8Ty.TypeName():
		g.emitRaw(
			asm.LSh.Imm(r1, 56),
			asm.ArSh.Imm(r1, 56),
		)
	case s16Ty.TypeName():
		g.emitRaw(
			asm.LSh.Imm(r1, 48),
			asm.ArSh.Imm(r1, 48),
		)
	}
	g.emitRaw(asm.StoreMem(asm.R10, g.stackTop, r1, asm.DWord))
	return nil
}

func (g *codeGenerator) emitBranch(
	reg1 asm.Register, ty1 *cgTypes.Type,
	reg2 asm.Register, ty2 *cgTypes.Type,
	op string,
	tmp asm.Register,
) error {

	var signed bool
	var alu32 bool
	switch {
	case ty1.TypeName() == s32Ty.TypeName() && ty2.TypeName() == s32Ty.TypeName(),
		ty1.TypeName() == s16Ty.TypeName() && ty2.TypeName() == s16Ty.TypeName(),
		ty1.TypeName() == s8Ty.TypeName() && ty2.TypeName() == s8Ty.TypeName():
		signed = true
		alu32 = true

	case ty1.TypeName() == s64Ty.TypeName() && ty2.TypeName() == s64Ty.TypeName():
		signed = true

	case ty1.TypeName() == u32Ty.TypeName() && ty2.TypeName() == u32Ty.TypeName(),
		ty1.TypeName() == u16Ty.TypeName() && ty2.TypeName() == u16Ty.TypeName(),
		ty1.TypeName() == u8Ty.TypeName() && ty2.TypeName() == u8Ty.TypeName():
		alu32 = true

	case ty1.TypeName() == u64Ty.TypeName() && ty2.TypeName() == u64Ty.TypeName():

	case ty1.TypeName() == boolTy.TypeName() && ty2.TypeName() == boolTy.TypeName() && (op == cgOperators.Equals || op == cgOperators.NotEquals):

	default:
		return fmt.Errorf("operation (%q) between types %s and %s is not supported", op, ty1.TypeName(), ty2.TypeName())
	}

	opcode := asm.InvalidJumpOp
	switch op {
	case cgOperators.Equals:
		opcode = asm.JEq
	case cgOperators.NotEquals:
		opcode = asm.JNE
	case cgOperators.Less:
		if signed {
			opcode = asm.JSLT
		} else {
			opcode = asm.JLT
		}
	case cgOperators.LessEquals:
		if signed {
			opcode = asm.JSLE
		} else {
			opcode = asm.JLE
		}
	case cgOperators.Greater:
		if signed {
			opcode = asm.JSGT
		} else {
			opcode = asm.JGT
		}
	case cgOperators.GreaterEquals:
		if signed {
			opcode = asm.JSGE
		} else {
			opcode = asm.JGE
		}
	default:
		return fmt.Errorf("inequality (%q) is not supported", op)
	}

	g.stackTop -= 8
	label := g.generateLabel()
	jmpInst := func() asm.Instruction {
		if alu32 {
			return opcode.Reg32(reg1, reg2, label)
		}
		return opcode.Reg(reg1, reg2, label)
	}
	g.emitRaw(
		asm.LoadImm(tmp, 1, asm.DWord),
		jmpInst(),
		asm.LoadImm(tmp, 0, asm.DWord),
		asm.StoreMem(asm.R10, g.stackTop, tmp, asm.DWord).WithSymbol(label),
	)
	return nil
}

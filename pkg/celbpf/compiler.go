// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	cgCommon "github.com/google/cel-go/common"
	cgAst "github.com/google/cel-go/common/ast"
	cgOperators "github.com/google/cel-go/common/operators"
	cgTypes "github.com/google/cel-go/common/types"
	cgRef "github.com/google/cel-go/common/types/ref"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type compiler struct {
	ast         *cgAst.AST
	src         cgCommon.Source
	cg          *codeGenerator
	args        []v1alpha1.KProbeArg
	data        []v1alpha1.KProbeArg
	arg_indexes []uint16
}

func newCompiler(ast *cgAst.AST, src cgCommon.Source, args, data []v1alpha1.KProbeArg, labelPrefix string) *compiler {
	return &compiler{
		ast:  ast,
		src:  src,
		cg:   newCodeGenerator(labelPrefix),
		args: args,
		data: data,
	}
}

func (c *compiler) compileLiteral(lit cgRef.Val) error {
	switch v := lit.(type) {
	case cgTypes.Bool:
		c.cg.emitPushBool(bool(v), scratchRegs[0])
		return nil
	case cgTypes.Int:
		// NB: ctTypes.Int is int64
		c.cg.emitPushInt64(int64(v), scratchRegs[0])
		return nil
	case cgTypes.Uint:
		// NB: ctTypes.UInt is uint64
		c.cg.emitPushInt64(int64(v), scratchRegs[0])
		return nil
	}
	return fmt.Errorf("compileLiteral: does not support %T", lit)
}

func (c *compiler) compileCall(expr cgAst.Expr) error {

	call := expr.AsCall()

	callArgs := call.Args()
	argTypes := make([]*cgTypes.Type, 0, len(callArgs))
	for _, arg := range callArgs {
		ty := c.ast.GetType(arg.ID())
		argTypes = append(argTypes, ty)
	}

	// setup emit call
	var emitCall func() error
	switch op := call.FunctionName(); op {
	case int32Fn:
		emitCall = func() error {
			return c.cg.emitS32(scratchRegs[0], argTypes[0])
		}
	case uint32Fn:
		emitCall = func() error {
			c.cg.emitU32(scratchRegs[0], argTypes[0])
			return nil
		}

	case cgOperators.Add:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.Add,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("addition %w", err)
			}
			return nil
		}

	case cgOperators.Subtract:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.Sub,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("subtraction %w", err)
			}
			return nil
		}

	case cgOperators.LogicalAnd:
		emitCall = func() error {
			return c.cg.emitAND(scratchRegs[0], scratchRegs[1])
		}

	case cgOperators.LogicalOr:
		emitCall = func() error {
			return c.cg.emitOR(scratchRegs[0], scratchRegs[1])
		}

	case cgOperators.LogicalNot:
		emitCall = func() error {
			// NB: scratchRegs[1] is not used but we pass it so that the implementation
			// can use it for an intemediate value.
			return c.cg.emitNot(scratchRegs[0], scratchRegs[1])
		}

	case cgOperators.Less, cgOperators.LessEquals,
		cgOperators.Greater, cgOperators.GreaterEquals,
		cgOperators.NotEquals, cgOperators.Equals:
		emitCall = func() error {
			// NB: scratchRegs[2] is not used but we pass it so that the implementation
			// can use it for an intemediate value.
			return c.cg.emitBranch(
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
				op,
				scratchRegs[2])

		}

	case andFn:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.And,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("bitwise AND %w", err)
			}
			return nil
		}

	case orFn:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.Or,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("bitwise OR %w", err)
			}
			return nil
		}

	case xorFn:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.Xor,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("bitwise XOR %w", err)
			}
			return nil
		}

	case notFn:
		emitCall = func() error {
			return c.cg.emitBitwiseNot(scratchRegs[0], argTypes[0])
		}

	case lshFn:
		emitCall = func() error {
			if err := c.cg.emitArithOp(
				asm.LSh,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("bitwise LSH %w", err)
			}
			return nil
		}

	case rshFn:
		emitCall = func() error {
			op := asm.RSh

			// Use Arithmetic shift to sign extend for signed types
			if argTypes[0].TypeName() == s32Ty.TypeName() || argTypes[0].TypeName() == s64Ty.TypeName() {
				op = asm.ArSh
			}
			if err := c.cg.emitArithOp(
				op,
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			); err != nil {
				return fmt.Errorf("bitwise RSH %w", err)
			}
			return nil
		}

	default:
		emitCall = func() error {
			return fmt.Errorf("compileCall: call %q (%+v) not supported", call.FunctionName(), call)
		}
	}

	// push arguments
	for _, arg := range callArgs {
		err := c.compileExpr(arg)
		if err != nil {
			return err
		}
	}

	// pop arguments (reverse order)
	for j := range callArgs {
		i := len(callArgs) - j - 1
		ty := argTypes[i]
		switch ty.TypeName() {
		case "int", "uint":
			c.cg.emitPopInt64(scratchRegs[i])
		case "bool":
			c.cg.emitPopBool(scratchRegs[i])
		case "s32":
			c.cg.emitPopS32(scratchRegs[i])
		case "u32":
			c.cg.emitPopU32(scratchRegs[i])
		default:
			return fmt.Errorf("unsupported argument type: %s", ty.TypeName())
		}
	}

	return emitCall()
}

func (c *compiler) compileArg(argIdx uint16) error {
	var arg v1alpha1.KProbeArg
	if int(argIdx) < len(c.args) {
		arg = c.args[argIdx]
	} else if int(argIdx) < len(c.args)+len(c.data) {
		arg = c.data[int(argIdx)-len(c.args)]
	} else {
		return fmt.Errorf("invalid argument (index %d): undefined", argIdx)
	}

	if !slices.Contains(c.arg_indexes, argIdx) {
		c.arg_indexes = append(c.arg_indexes, argIdx)
	}

	converted_type := convertType(arg)

	if converted_type == unsupportedTy {
		return fmt.Errorf("arg%d has unsupported type", argIdx)
	}

	if err := c.cg.pushArg(converted_type, argIdx, scratchRegs[0], scratchRegs[1]); err != nil {
		return fmt.Errorf("invalid argument (arg%d): %w", argIdx, err)
	}
	return nil
}

func (c *compiler) compileIdent(s string) error {
	if strings.HasPrefix(s, "arg") {
		idx, err := strconv.ParseUint(s[3:], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid argument (%s): %w", s, err)
		}
		return c.compileArg(uint16(idx))
	}
	if strings.HasPrefix(s, "data") {
		idx, err := strconv.ParseUint(s[4:], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid data argument (%s): %w", s, err)
		}
		return c.compileArg(uint16(len(c.args) + int(idx)))
	}
	return fmt.Errorf("BUG: ident %q unknown", s)
}

func (c *compiler) compileExpr(expr cgAst.Expr) error {
	switch expr.Kind() {
	case cgAst.LiteralKind:
		return c.compileLiteral(expr.AsLiteral())
	case cgAst.CallKind:
		return c.compileCall(expr)
	case cgAst.ComprehensionKind:
		return errors.New("expression Kind 'ComprehensionKind' not supported")
	case cgAst.IdentKind:
		return c.compileIdent(expr.AsIdent())
	case cgAst.ListKind:
		return errors.New("expression Kind 'ListKind' not supported")
	case cgAst.MapKind:
		return errors.New("expression Kind 'MapKind' not supported")
	case cgAst.SelectKind:
		return errors.New("expression Kind 'SelectKind' not supported")
	case cgAst.StructKind:
		return errors.New("expression Kind 'StructKind' not supported")

	}
	return fmt.Errorf("unsupported CEL expr: %d (%+v)", expr.Kind(), expr)
}

func (c *compiler) compile() (asm.Instructions, []uint16, error) {
	expr := c.ast.Expr()
	if cgAst.NavigateExpr(c.ast, expr).Type().Kind() != cgTypes.BoolKind {
		return nil, nil, errors.New("expecting CEL expression to return bool")
	}
	if err := c.compileExpr(expr); err != nil {
		return nil, nil, fmt.Errorf("failed to compile CEL expression: %w", err)
	}
	c.cg.emitPopBool(asm.R0)
	c.cg.emitRaw(asm.Return())

	return c.cg.instructions(), c.arg_indexes, nil
}

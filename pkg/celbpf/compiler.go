// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	cgCommon "github.com/google/cel-go/common"
	cgAst "github.com/google/cel-go/common/ast"
	cgOperators "github.com/google/cel-go/common/operators"
	cgTypes "github.com/google/cel-go/common/types"
	cgRef "github.com/google/cel-go/common/types/ref"
)

type compiler struct {
	ast  *cgAst.AST
	src  cgCommon.Source
	cg   *codeGenerator
	args []exprArg
}

func newCompiler(ast *cgAst.AST, src cgCommon.Source, args []exprArg, labelPrefix string) *compiler {
	return &compiler{
		ast:  ast,
		src:  src,
		cg:   newCodeGenerator(labelPrefix),
		args: args,
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
	case cgOperators.Equals:
		emitCall = func() error {
			c.cg.emitBranchEquals(scratchRegs[0], scratchRegs[1])
			return nil
		}
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
			return c.cg.emitAdd(
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			)
		}

	case cgOperators.Subtract:
		emitCall = func() error {
			return c.cg.emitSub(
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
			)
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
		cgOperators.NotEquals:
		emitCall = func() error {
			// NB: scratchRegs[2] is not used but we pass it so that the implementation
			// can use it for an intemediate value.
			return c.cg.emitInequality(
				scratchRegs[0], argTypes[0],
				scratchRegs[1], argTypes[1],
				op,
				scratchRegs[2])

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

func (c *compiler) compileArg(argIdx int) error {
	if argIdx >= len(c.args) {
		return fmt.Errorf("invalid argument (arg%d): undefined", argIdx)
	}

	arg := c.args[argIdx]
	if err := c.cg.pushArg(arg.ty, arg.argOffset, scratchRegs[0], scratchRegs[1]); err != nil {
		return fmt.Errorf("invalid argument (arg%d): %w", argIdx, err)
	}
	return nil
}

func (c *compiler) compileIdent(s string) error {
	if strings.HasPrefix(s, "arg") {
		idx, err := strconv.Atoi(s[3:])
		if err != nil {
			return fmt.Errorf("invalid argument (%s): %w", s, err)
		}
		return c.compileArg(idx)
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

func (c *compiler) compile() (asm.Instructions, error) {
	expr := c.ast.Expr()
	if cgAst.NavigateExpr(c.ast, expr).Type().Kind() != cgTypes.BoolKind {
		return nil, errors.New("expecting CEL expression to return bool")
	}
	if err := c.compileExpr(expr); err != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
	}
	c.cg.emitPopBool(asm.R0)
	c.cg.emitRaw(asm.Return())

	return c.cg.instructions(), nil
}

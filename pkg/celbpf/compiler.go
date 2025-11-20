// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Cel -> BPF code generation
// Heavily based on an earlier implementation by Yutaro Hayakawa <yutaro.hayakawa@isovalent.com>
package celbpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
	cgCommon "github.com/google/cel-go/common"
	cgAst "github.com/google/cel-go/common/ast"
	cgOperators "github.com/google/cel-go/common/operators"
	cgTypes "github.com/google/cel-go/common/types"
	cgRef "github.com/google/cel-go/common/types/ref"
)

type compiler struct {
	ast *cgAst.AST
	src cgCommon.Source
	cg  *codeGenerator
}

func newCompiler(ast *cgAst.AST, src cgCommon.Source, labelPrefix string) *compiler {
	return &compiler{
		ast: ast,
		src: src,
		cg:  newCodeGenerator(labelPrefix),
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

	// setup emit call
	var emitCall func()
	switch call.FunctionName() {
	case cgOperators.Equals:
		emitCall = func() {
			c.cg.emitBranchEquals(scratchRegs[0], scratchRegs[1])
		}
	default:
		return fmt.Errorf("compileCall: call %+v not supported", call)
	}

	// push argument
	callArgs := call.Args()
	argTypes := make([]*cgTypes.Type, 0, len(callArgs))
	for _, arg := range callArgs {
		ty := c.ast.GetType(arg.ID())
		err := c.compileExpr(arg)
		if err != nil {
			return err
		}
		argTypes = append(argTypes, ty)
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
		default:
			return fmt.Errorf("unsupported argument type: %s", ty.TypeName())
		}
	}

	emitCall()
	return nil
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
		return errors.New("expression Kind 'IdentKind' not supported")
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

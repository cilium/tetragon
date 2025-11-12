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
	cgTypes "github.com/google/cel-go/common/types"
	cgRef "github.com/google/cel-go/common/types/ref"
)

type compiler struct {
	ast *cgAst.AST
	src cgCommon.Source
	cg  *codeGenerator
}

func newCompiler(ast *cgAst.AST, src cgCommon.Source) *compiler {
	return &compiler{
		ast: ast,
		src: src,
		cg:  newCodeGenerator(),
	}
}

func (c *compiler) compileLiteral(lit cgRef.Val) error {
	switch v := lit.(type) {
	case cgTypes.Bool:
		c.cg.emitPushBool(bool(v))
		return nil
	}
	return fmt.Errorf("compileLiteral: does not support %T", lit)
}

func (c *compiler) compileExpr(expr cgAst.Expr) error {
	switch expr.Kind() {
	case cgAst.LiteralKind:
		return c.compileLiteral(expr.AsLiteral())
	}
	return fmt.Errorf("unsupported CEL expr: %d (%+v)", expr.Kind(), expr)
}

func (c *compiler) compile() (asm.Instructions, error) {
	expr := c.ast.Expr()
	if cgAst.NavigateExpr(c.ast, expr).Type().Kind() != cgTypes.BoolKind {
		return nil, errors.New("expecting CEL expression to return bool")
	}
	if err := c.compileExpr(expr); err != nil {
		return nil, err
	}
	c.cg.emitPopBool(asm.R0)
	c.cg.emitRaw(asm.Return())

	return c.cg.instructions(), nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"
	"reflect"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/google/cel-go/cel"
	"github.com/sirupsen/logrus"
	celk8s "k8s.io/apiserver/pkg/cel/library"
)

// compile will parse and check an expression `expr` against a given
// environment `env` and determine whether the resulting type of the expression
// matches the `exprType` provided as input.
// Copied from
// https://github.com/google/cel-go/blob/338b3c80e688f7f44661d163c0dbc02eb120dcb7/codelab/solution/codelab.go#LL385C1-L399C2
// with modifications
func compile(env *cel.Env, expr string, celType *cel.Type) (*cel.Ast, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	// Type-check the expression for correctness.
	checked, iss := env.Check(ast)
	// Report semantic errors, if present.
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if checked.OutputType() != celType {
		return nil, fmt.Errorf(
			"got %q, wanted %q result type",
			checked.OutputType(), celType)
	}
	return ast, nil
}

func EvalCEL(ctx context.Context, program cel.Program, event *tetragon.GetEventsResponse) (bool, error) {
	out, _, err := program.ContextEval(ctx, helpers.ProcessEventMap(event))
	if err != nil {
		return false, fmt.Errorf("error running CEL program: %w", err)
	}
	v, err := out.ConvertToNative(reflect.TypeOf(false))
	if err != nil {
		return false, fmt.Errorf("invalid conversion in CEL program: %w", err)
	}
	b, ok := v.(bool)
	if ok && b {
		return true, nil
	}
	return false, nil
}

func (c *CELExpressionFilter) filterByCELExpression(ctx context.Context, log logrus.FieldLogger, exprs []string) (hubbleFilters.FilterFunc, error) {
	var programs []cel.Program
	for _, expr := range exprs {
		prg, err := c.CompileCEL(expr)
		if err != nil {
			return nil, err
		}
		programs = append(programs, prg)
	}

	return func(ev *v1.Event) bool {
		if ev == nil {
			return false
		}
		response, ok := ev.Event.(*tetragon.GetEventsResponse)
		if !ok {
			return false
		}
		for _, prg := range programs {
			match, err := EvalCEL(ctx, prg, response)
			if err != nil {
				log.Error(err)
				return false
			}
			if match {
				return true
			}
		}
		return false
	}, nil
}

// CELExpressionFilter implements filtering based on CEL (common expression
// language) expressions
type CELExpressionFilter struct {
	log    logrus.FieldLogger
	celEnv *cel.Env
}

func NewCELExpressionFilter(log logrus.FieldLogger) *CELExpressionFilter {
	responseTypeMap := helpers.ResponseTypeMap()
	options := []cel.EnvOption{
		cel.Container("tetragon"),
		// Import IP and CIDR related helpers from k8s CEL library
		celk8s.IP(),
		celk8s.CIDR(),
	}
	for key, val := range responseTypeMap {
		name := string(val.ProtoReflect().Descriptor().FullName())
		options = append(options, cel.Variable(key, cel.ObjectType(name)))
		options = append(options, cel.Types(val))
	}
	celEnv, err := cel.NewEnv(options...)
	if err != nil {
		panic(fmt.Sprintf("error creating CEL env %s", err))
	}
	return &CELExpressionFilter{
		log:    log,
		celEnv: celEnv,
	}
}

func (c *CELExpressionFilter) CompileCEL(expr string) (cel.Program, error) {
	// we want filters to be boolean expressions, so check the type of the
	// expression before proceeding
	ast, err := compile(c.celEnv, expr, cel.BoolType)
	if err != nil {
		return nil, fmt.Errorf("error compiling CEL expression: %w", err)
	}

	prg, err := c.celEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("error building CEL program: %w", err)
	}
	return prg, nil
}

// OnBuildFilter builds a CEL expression filter.
func (c *CELExpressionFilter) OnBuildFilter(ctx context.Context, f *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	if exprs := f.GetCelExpression(); exprs != nil {
		filter, err := c.filterByCELExpression(ctx, c.log, exprs)
		if err != nil {
			return nil, err
		}
		return []hubbleFilters.FilterFunc{filter}, nil
	}
	return []hubbleFilters.FilterFunc{}, nil
}

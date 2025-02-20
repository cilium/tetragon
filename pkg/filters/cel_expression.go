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

func (t *CELExpressionFilter) filterByCELExpression(ctx context.Context, log logrus.FieldLogger, exprs []string) (hubbleFilters.FilterFunc, error) {
	var programs []cel.Program
	for _, expr := range exprs {
		// we want filters to be boolean expressions, so check the type of the
		// expression before proceeding
		ast, err := compile(t.celEnv, expr, cel.BoolType)
		if err != nil {
			return nil, fmt.Errorf("error compiling CEL expression: %w", err)
		}

		prg, err := t.celEnv.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("error building CEL program: %w", err)
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
			out, _, err := prg.ContextEval(ctx, helpers.ProcessEventMap(response))
			if err != nil {
				log.Errorf("error running CEL program %s", err)
				return false
			}

			v, err := out.ConvertToNative(reflect.TypeOf(false))
			if err != nil {
				log.Errorf("invalid conversion in CEL program: %s", err)
				return false
			}
			b, ok := v.(bool)
			if ok && b {
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

// OnBuildFilter builds a CEL expression filter.
func (t *CELExpressionFilter) OnBuildFilter(ctx context.Context, f *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	if exprs := f.GetCelExpression(); exprs != nil {
		filter, err := t.filterByCELExpression(ctx, t.log, exprs)
		if err != nil {
			return nil, err
		}
		return []hubbleFilters.FilterFunc{filter}, nil
	}
	return []hubbleFilters.FilterFunc{}, nil
}

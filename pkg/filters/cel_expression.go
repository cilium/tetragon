// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/google/cel-go/cel"
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

func EvalCEL(ctx context.Context, program cel.Program, eventMap map[string]any) (bool, error) {
	out, _, err := program.ContextEval(ctx, eventMap)
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

type celProgEv struct {
	program    cel.Program
	eventNames []string
}

func (c *CELExpressionFilter) filterByCELExpression(ctx context.Context, log logger.FieldLogger, exprs []string) (FilterFunc, error) {
	var programs []celProgEv
	for _, expr := range exprs {
		prog, eventNames, err := c.CompileCEL(expr)
		if err != nil {
			return nil, err
		}
		programs = append(programs, celProgEv{program: prog, eventNames: eventNames})
	}

	// Create a single empty (all values are nil) process event map
	// this removes the need to do map allocations inside the loop
	eventMap := helpers.ProcessEventMapEmpty()
	return func(ev *event.Event) bool {
		if ev == nil {
			return false
		}
		response, ok := ev.Event.(*tetragon.GetEventsResponse)
		if !ok {
			return false
		}

		// First we get the details about the event such as the name ("process_exec")
		// and a casted pointer (*tetragon.ProcessExec) to the actual event. The third
		// return value is always nil but casted to the appropriate type in order
		// not to cause issues with the CEL evaluation.
		evName, evData, evDefer := helpers.ProcessEventMapTuple(response)
		// set to the empty map the appropriate value in the correct position
		eventMap[evName] = evData
		defer func() {
			// When we are done make that nil again.
			// evDefer is nil but casted to the appropriate type (i.e. (*tetragon.ProcessExec)(nil)).
			// If we used nil here (without the cast) we were getting errors similar to:
			// "error running CEL program: unsupported field selection target: (<nil>)<nil>"
			eventMap[evName] = evDefer
		}()

		for _, prg := range programs {
			for _, n := range prg.eventNames { // list of events that are needed to evaluate that rule
				if !reflect.ValueOf(eventMap[n]).IsNil() { // is the incoming event related to that alert?
					match, err := EvalCEL(ctx, prg.program, eventMap)
					if err != nil {
						log.Error("EvalCEL Error", logfields.Error, err)
						return false
					}
					if match {
						return true
					}
					break
				}
			}
		}
		return false
	}, nil
}

// CELExpressionFilter implements filtering based on CEL (common expression
// language) expressions
type CELExpressionFilter struct {
	log       logger.FieldLogger
	evToProto map[string]string // i.e. "tetragon.ProcessExec" -> "process_exec" mappings
	celEnv    *cel.Env
}

func NewCELExpressionFilter(log logger.FieldLogger) *CELExpressionFilter {
	responseTypeMap := helpers.ResponseTypeMap()
	evToProto := map[string]string{}
	options := []cel.EnvOption{
		cel.Container("tetragon"),
		// Import IP and CIDR related helpers from k8s CEL library
		celk8s.IP(),
		celk8s.CIDR(),
	}
	for key, val := range responseTypeMap {
		name := string(val.ProtoReflect().Descriptor().FullName())
		evToProto[name] = key
		options = append(options, cel.Variable(key, cel.ObjectType(name)))
		options = append(options, cel.Types(val))
	}
	celEnv, err := cel.NewEnv(options...)
	if err != nil {
		panic(fmt.Sprintf("error creating CEL env %s", err))
	}
	return &CELExpressionFilter{
		log:       log,
		evToProto: evToProto,
		celEnv:    celEnv,
	}
}

// The second return value '[]string' includes the events that are related to
// the CEL expr that we compile (i.e. process_exec, process_kprobe etc.).
func (c *CELExpressionFilter) CompileCEL(expr string) (cel.Program, []string, error) {
	// we want filters to be boolean expressions, so check the type of the
	// expression before proceeding
	ast, err := compile(c.celEnv, expr, cel.BoolType)
	if err != nil {
		return nil, nil, fmt.Errorf("error compiling CEL expression: %w", err)
	}

	uniqEvents := map[string]struct{}{}            // keeps all unique json names (i.e. process_exec) of the events that the ast includes
	for _, tp := range ast.NativeRep().TypeMap() { // TypeMap() is a map that contains as values the proto names of the events related to that ast (i.e. tetragon.ProcessExec)
		if ev, ok := c.evToProto[tp.TypeName()]; ok { // we get the json name (i.e. process_exec) from the proto event name (i.e. tetragon.ProcessExec)
			uniqEvents[ev] = struct{}{}
		}
	}
	// we use uniqEvents before calling EvalCEL to check if this program is related to the generated event

	prg, err := c.celEnv.Program(ast)
	if err != nil {
		return nil, nil, fmt.Errorf("error building CEL program: %w", err)
	}
	return prg, slices.Collect(maps.Keys(uniqEvents)), nil
}

// OnBuildFilter builds a CEL expression filter.
func (c *CELExpressionFilter) OnBuildFilter(ctx context.Context, f *tetragon.Filter) ([]FilterFunc, error) {
	if exprs := f.GetCelExpression(); exprs != nil {
		filter, err := c.filterByCELExpression(ctx, c.log, exprs)
		if err != nil {
			return nil, err
		}
		return []FilterFunc{filter}, nil
	}
	return []FilterFunc{}, nil
}

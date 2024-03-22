// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
)

type celProg struct {
	p      cel.Program
	values map[string]interface{}
}

func celUserExpr(expr string) (*celProg, error) {
	env, err := cel.NewEnv(
		cel.Variable("annotations", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("annotations_namespace_key", cel.StringType),
	)

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile `%s`: %w", expr, err)
	}

	p, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	return &celProg{
		p: p,
		values: map[string]interface{}{
			"annotations_namespace_keys": cliConf.AnnNamespaceKeys,
		},
	}, nil
}

func celAllowNamespaces(vals []string) (*celProg, error) {
	env, err := cel.NewEnv(
		cel.Variable("annotations", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("annotations_namespace_keys", cel.ListType(cel.StringType)),
		cel.Variable("allow_labels", cel.ListType(cel.StringType)),
	)
	if err != nil {
		return nil, err
	}

	//expr := `!(annotations_namespace_key in annotations && annotations[annotations_namespace_key] in allow_labels)`
	expr := `annotations_namespace_keys.all(key, !(key in annotations && annotations[key] in allow_labels))`
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile `%s`: %w", expr, issues.Err())
	}

	p, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	return &celProg{
		p: p,
		values: map[string]interface{}{
			"allow_labels":               vals,
			"annotations_namespace_keys": cliConf.AnnNamespaceKeys,
		},
	}, nil
}

func (prog *celProg) RunFailCheck(annotations map[string]string) (bool, error) {
	vals := make(map[string]interface{}, len(prog.values)+1)
	for k, v := range prog.values {
		vals[k] = v
	}
	vals["annotations"] = annotations

	out, _, err := prog.p.Eval(vals)
	if err != nil {
		return true, err
	}

	refType := reflect.TypeOf(true)
	val, err := out.ConvertToNative(refType)
	if err != nil {
		return true, fmt.Errorf("cannot convert value to bool: %w", err)
	}

	return val.(bool), nil
}

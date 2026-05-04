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
	if err != nil {
		return nil, err
	}

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
			"annotations_namespace_keys": cliConf.AnnNamespaceKeys,
		},
	}, nil
}

// celAllowNamespacesWithPatterns returns a *celProg that allows containers
// whose pod namespace matches any of the provided exact names (namespaces) or
// any of the provided RE2 regex patterns (patterns). Patterns perform substring
// matching by default; use ^ and $ anchors for full-string matching. Either
// slice may be empty or nil; if both are empty every container is failed (safe default).
//
// Behaviour summary:
//   - Namespace key missing from annotations  -> fail (true)
//   - Namespace matches an exact allow entry  -> do not fail (false)
//   - Namespace matches a regex pattern       -> do not fail (false)
//   - Namespace matches neither               -> fail (true)
func celAllowNamespacesWithPatterns(namespaces []string, patterns []string) (*celProg, error) {
	env, err := cel.NewEnv(
		cel.Variable("annotations", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("annotations_namespace_keys", cel.ListType(cel.StringType)),
		cel.Variable("allow_namespaces", cel.ListType(cel.StringType)),
		cel.Variable("allow_namespace_patterns", cel.ListType(cel.StringType)),
	)
	if err != nil {
		return nil, err
	}

	// The expression fails (returns true) unless a matching namespace key is
	// found AND the namespace is in the exact allow list or matches a regex pattern.
	expr := `annotations_namespace_keys.all(key,
		!(key in annotations && (
			annotations[key] in allow_namespaces ||
			allow_namespace_patterns.exists(p, annotations[key].matches(p))
		)))`
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile allow-namespaces expr `%s`: %w", expr, issues.Err())
	}

	p, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	return &celProg{
		p: p,
		values: map[string]interface{}{
			"annotations_namespace_keys": cliConf.AnnNamespaceKeys,
			"allow_namespaces":           namespaces,
			"allow_namespace_patterns":   patterns,
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

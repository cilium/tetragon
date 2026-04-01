// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

type celProg struct {
	p      cel.Program
	values map[string]interface{}
}

// namespaceMatchesGlob reports whether ns matches the glob pattern p.
// The only supported wildcard is a single '*', which matches any sequence of
// characters. Patterns with more than one '*' are rejected at construction time
// (see celAllowNamespacesWithPatterns), so this function assumes at most one.
func namespaceMatchesGlob(ns, p string) bool {
	if p == "*" {
		return true
	}
	if idx := strings.Index(p, "*"); idx >= 0 {
		prefix, suffix := p[:idx], p[idx+1:]
		// The length guard prevents a false match when prefix and suffix
		// overlap on a short string, e.g. pattern "foo-*-bar" against
		// namespace "foo-bar": both HasPrefix and HasSuffix would return
		// true even though there are no characters left for '*' to match.
		return len(ns) >= len(prefix)+len(suffix) &&
			strings.HasPrefix(ns, prefix) &&
			strings.HasSuffix(ns, suffix)
	}
	return ns == p
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

// celAllowNamespacesWithPatterns returns a *celProg that allows containers
// whose pod namespace matches any of the provided exact names (namespaces) or
// any of the provided glob patterns (patterns). Glob patterns support a single
// '*' wildcard (for example "kube-*", "*-system", "*-monitoring-*"). Patterns
// with more than one '*' are rejected. Either slice may be empty or nil; if
// both are empty every container is failed (safe default).
//
// Behaviour summary:
//   - Namespace key missing from annotations  -> fail (true)
//   - Namespace matches an exact allow entry  -> do not fail (false)
//   - Namespace matches a glob pattern        -> do not fail (false)
//   - Namespace matches neither               -> fail (true)
func celAllowNamespacesWithPatterns(namespaces []string, patterns []string) (*celProg, error) {
	for _, p := range patterns {
		if strings.Count(p, "*") > 1 {
			return nil, fmt.Errorf("invalid namespace pattern %q: only a single '*' wildcard is supported", p)
		}
	}

	globFn := cel.Function("namespace_matches_glob",
		cel.Overload("namespace_matches_glob_string_string",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.BinaryBinding(func(ns ref.Val, p ref.Val) ref.Val {
				return types.Bool(namespaceMatchesGlob(
					ns.Value().(string),
					p.Value().(string),
				))
			}),
		),
	)

	env, err := cel.NewEnv(
		cel.Variable("annotations", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("annotations_namespace_keys", cel.ListType(cel.StringType)),
		cel.Variable("allow_namespaces", cel.ListType(cel.StringType)),
		cel.Variable("allow_patterns", cel.ListType(cel.StringType)),
		globFn,
	)
	if err != nil {
		return nil, err
	}

	// The expression fails (returns true) unless a matching namespace key is
	// found AND the namespace is in the exact allow list or matches a glob.
	expr := `annotations_namespace_keys.all(key,
		!(key in annotations && (
			annotations[key] in allow_namespaces ||
			allow_patterns.exists(p, namespace_matches_glob(annotations[key], p))
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
			"allow_patterns":             patterns,
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

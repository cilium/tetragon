// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package tracingpolicy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/message"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
)

const tpURL = "file:///tracingpolicy"

var tpSchema *jsonschema.Schema

type memLoader struct{}

func (m *memLoader) Load(url string) (any, error) {
	switch url {
	case tpURL:
		return bytesToMap(tracingpolicyJSONSchema)
	}
	return nil, fmt.Errorf("wrong loader url: %s", url)
}

func init() {
	celEnv, err := cel.NewEnv(
		cel.Variable("self", cel.DynType),
	)
	if err != nil {
		panic(fmt.Errorf("failed to create CEL env: %w", err))
	}

	c := jsonschema.NewCompiler()
	c.AssertVocabs() // Allow custom keywords
	c.RegisterVocabulary(celVocabulary(celEnv))
	c.UseLoader(&memLoader{})
	tpSchema = c.MustCompile(tpURL)
}

type celRule struct {
	rule    string
	message string
	prg     cel.Program
}

type celSchema struct {
	rules []celRule
}

type celError struct {
	err string
}

func (e *celError) KeywordPath() []string                     { return []string{"x-kubernetes-validations"} }
func (e *celError) LocalizedString(_ *message.Printer) string { return e.err }

func (s *celSchema) Validate(ctx *jsonschema.ValidatorContext, v any) {
	for _, rule := range s.rules {
		out, _, err := rule.prg.Eval(map[string]any{"self": v})
		if err != nil {
			logger.GetLogger().Warn("failed to evaluate CEL rule", "rule", rule.rule, "error", err)
			continue
		}
		if out != types.True {
			ctx.AddError(&celError{err: rule.message})
		}
	}
}

func celVocabulary(celEnv *cel.Env) *jsonschema.Vocabulary {
	return &jsonschema.Vocabulary{
		URL: "https://kubernetes.io/x-kubernetes-validations",
		Compile: func(ctx *jsonschema.CompilerContext, obj map[string]any) (jsonschema.SchemaExt, error) {
			val, ok := obj["x-kubernetes-validations"]
			if !ok {
				return nil, nil
			}
			rules, ok := val.([]any)
			if !ok {
				return nil, nil
			}
			var celRules []celRule
			for _, r := range rules {
				m, ok := r.(map[string]any)
				if !ok {
					continue
				}
				ruleStr, isStr := m["rule"].(string)
				if !isStr {
					logger.GetLogger().Warn("invalid x-kubernetes-validations rule field type", "rule", r)
				}
				msg, isStr := m["message"].(string)
				if !isStr {
					logger.GetLogger().Warn("invalid x-kubernetes-validations message field type", "rule", r)
				}
				if ruleStr != "" {
					ast, issues := celEnv.Compile(ruleStr)
					if issues != nil && issues.Err() != nil {
						return nil, issues.Err()
					}
					prg, err := celEnv.Program(ast)
					if err != nil {
						return nil, err
					}
					celRules = append(celRules, celRule{
						rule:    ruleStr,
						message: msg,
						prg:     prg,
					})
				}
			}
			if len(celRules) == 0 {
				return nil, nil
			}
			return &celSchema{rules: celRules}, nil
		},
	}
}

func bytesToMap(b []byte) (any, error) {
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}

// FromYAML parses a YAML string into a TracingPolicy -- !k8s version
func FromYAML(data string) (TracingPolicy, error) {
	kind, jsonBytes, err := nok8s.ParseK8sObj(data)
	if err != nil {
		return nil, err
	}

	switch kind {
	case v1alpha1.TPKindDefinition:
		var gtp GenericTracingPolicy
		if err := json.Unmarshal(jsonBytes, &gtp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TracingPolicy: %w", err)
		}

		m, err := bytesToMap(jsonBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to convert TracingPolicy to map: %w", err)
		}

		if err = tpSchema.Validate(m); err != nil {
			return nil, fmt.Errorf("failed to validate TracingPolicy: %w", err)
		}

		return &gtp, nil
	case v1alpha1.TPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tracing policies not supported in non-k8s builds: %s", kind)
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}

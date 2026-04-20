// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"bytes"
	"fmt"
	"text/template"
)

// Builder offers an ergonomic way to build policy tests (using method chaining)
type Builder struct {
	policytest *T
}

func NewBuilder(name string) *Builder {
	return &Builder{
		policytest: &T{
			Name: name,
		}}
}

func (b *Builder) WithLabels(labels ...string) *Builder {
	for _, lbl := range labels {
		b.policytest.Labels = append(b.policytest.Labels, Label(lbl))
	}
	return b
}

func (b *Builder) WithParameter(p Parameter) *Builder {
	b.policytest.Params = append(b.policytest.Params, p)
	return b
}

// WithPolicyTemplate adds a policy to a policy test using a text template.
//
// In the template, the following functions are supported
//   - testBinary: generate a test binary path from the binary name (Conf.TestBinary())
func (b *Builder) WithPolicyTemplate(tmpl string) *Builder {
	policyTest := b.policytest
	policyTest.Policy = func(c *Conf) (Policy, error) {
		funcMap := template.FuncMap{
			"testBinary": func(s string) string {
				return c.TestBinary(s)
			},
		}
		t, err := template.New("testpolicy").Funcs(funcMap).Parse(tmpl)
		if err != nil {
			return Policy(""), fmt.Errorf("failed to parse template: %w", err)
		}

		// fill in params
		params := make(map[string]any)
		for _, p := range policyTest.Params {
			val, ok := c.TestConf.ParamValues[p.Name]
			if !ok {
				val = p.Default
			}
			params[p.Name] = val
		}

		var buf bytes.Buffer
		err = t.Execute(&buf, params)
		if err != nil {
			return Policy(""), fmt.Errorf("failed to execute template: %w", err)
		}
		return Policy(buf.String()), nil
	}
	return b
}

func (b *Builder) WithSkip(fn func(*SkipInfo) string) *Builder {
	b.policytest.ShouldSkip = fn
	return b
}

// WithSetup registers a function that runs before the observer is loaded.
// The returned cleanup function, if non-nil, is called after the test completes.
func (b *Builder) WithSetup(fn func() func()) *Builder {
	b.policytest.Setup = fn
	return b
}

// Add a scenario to the builder
func (b *Builder) AddScenario(fn func(c *Conf) *Scenario) *Builder {
	b.policytest.Scenarios = append(b.policytest.Scenarios, fn)
	return b
}

// RegisterAtInit registers the policy at initilization time (i.e., in init or in top-level global
// declaration)
// NB: return something so that we can use this in a var top-level declaration
func (b *Builder) RegisterAtInit() any {
	RegisterPolicyTestAtInit(b.policytest)
	return nil
}

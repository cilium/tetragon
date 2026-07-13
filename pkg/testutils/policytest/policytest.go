// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

// Trigger is a way to trigger a policy
type Trigger interface {
	Trigger(ctx context.Context) error
}

type Scenario struct {
	Name                 string
	Trigger              Trigger
	EventChecker         ec.MultiEventChecker
	ActCountChecker      ActionCounts
	ExpectCheckerFailure bool
}

// Policies are represented as strings, because that's how they are loaded via gRPC
type Policy string

type PolicyCleanupFn func()

type Label string

type SkipInfo struct {
	AgentInfo   *tetragoninfo.Info
	ParamValues ParamVals
}

type Parameter struct {
	Name    string
	Default any
	Help    string
	// Values, if set, is used to generate values for this parameter when testing.
	// Values is meant to hold all values (including the one specified by Default)
	Values []any
}

func (p *Parameter) HelpString() string {
	if len(p.Values) == 0 {
		return fmt.Sprintf("%s: %s (default:%s)", p.Name, p.Help, p.Default)
	}
	values := make([]string, 0, len(p.Values))
	for _, v := range p.Values {
		values = append(values, fmt.Sprintf("%v", v))
	}
	return fmt.Sprintf("%s: %s (values:%q default:%q)", p.Name, p.Help, strings.Join(values, ","), p.Default)
}

// T defines a policy test
type T struct {
	// Name returns the name of the test
	Name string
	// Labels is a set of labels for the test
	Labels []Label

	// ShouldSkip returns a non-empty string if the policy test is to be skipped.
	// In that case, the string contains the reason that the test was skipped.
	ShouldSkip func(info *SkipInfo) string

	// Policy generates a policy for this test
	Policy func(c *Conf) (Policy, PolicyCleanupFn, error)

	Params []Parameter

	// Scenarios returns a list of scenarios to test the generated policy
	Scenarios []func(c *Conf) *Scenario
}

type ScenarioRes struct {
	Name            string    `json:"name"`
	TriggerErr      JSONError `json:"trigger_error"`
	CheckerErr      JSONError `json:"checker_error"`
	ActionCountsErr JSONError `json:"action_counts_error"`
}

func (sr *ScenarioRes) Err() error {
	var err error
	if sr.TriggerErr.Err != nil {
		err = fmt.Errorf("trigger error: %w", sr.TriggerErr.Err)
	}
	if sr.CheckerErr.Err != nil {
		err = addErr(err, "checker error", sr.CheckerErr.Err)
	}
	if sr.ActionCountsErr.Err != nil {
		err = addErr(err, "action counts error", sr.ActionCountsErr.Err)
	}
	return err
}

func addErr(err error, prefix1 string, err1 error) error {
	if err1 == nil {
		return err
	}

	if err == nil {
		return fmt.Errorf("%s: %w", prefix1, err1)
	}

	return fmt.Errorf("%w, %s: %w", err, prefix1, err1)
}

// Result of a policytest (T)
type Result struct {
	Skipped      string        `json:"skipped,omitempty"` // if not empty, the policy was skipped and the string contains the reason
	Err          JSONError     `json:"error"`
	ScenariosRes []ScenarioRes `json:"scenarios"`
	TotalTime    time.Duration `json:"total_time"`
}

// AllParamValues returns a sequence of
func (t *T) AllParamValues() iter.Seq[ParamVals] {
	return allParamValues(t.Params)
}

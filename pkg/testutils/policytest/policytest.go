// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"
	"iter"
	"reflect"
	"strconv"
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

// CLIFlag describes an agent CLI flag value required by a policy test.
type CLIFlag struct {
	Name  string
	Value any
}

// CheckCLIFlags returns a skip reason when agent configuration does not satisfy
// the required CLI flags.
func CheckCLIFlags(info *tetragoninfo.Info, flags []CLIFlag) string {
	if info == nil {
		return ""
	}
	satisfied := true
	for _, flag := range flags {
		actual, ok := info.Conf[flag.Name]
		if !ok || !cliFlagValuesEqual(actual, flag.Value) {
			satisfied = false
		}
	}
	if satisfied {
		return ""
	}
	required := make([]string, 0, len(flags))
	for _, flag := range flags {
		required = append(required, fmt.Sprintf("--%s=%s", flag.Name, formatCLIFlagValue(flag.Value)))
	}
	return "agent does not satisfy required CLI flags: " + strings.Join(required, " ")
}

func formatCLIFlagValue(value any) string {
	if values, ok := value.([]int); ok {
		parts := make([]string, len(values))
		for i, value := range values {
			parts[i] = strconv.Itoa(value)
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(value)
}

func cliFlagValuesEqual(actual, expected any) bool {
	if reflect.DeepEqual(actual, expected) {
		return true
	}
	switch expected := expected.(type) {
	case int:
		actual, ok := actual.(int64)
		return ok && actual == int64(expected)
	case float64:
		actualString, ok := actual.(string)
		if !ok {
			return false
		}
		actualFloat, err := strconv.ParseFloat(actualString, 64)
		return err == nil && actualFloat == expected
	case []int:
		actual, ok := actual.([]any)
		if !ok || len(actual) != len(expected) {
			return false
		}
		for i, value := range actual {
			number, ok := value.(float64)
			if !ok || number != float64(expected[i]) {
				return false
			}
		}
		return true
	}
	return false
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
	// CLIFlags lists agent CLI flag values required to run this test.
	CLIFlags []CLIFlag

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

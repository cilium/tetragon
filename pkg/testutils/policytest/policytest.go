// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

// Trigger is a way to trigger a policy
type Trigger interface {
	Trigger(ctx context.Context) error
}

type Scenario struct {
	Name         string
	Trigger      Trigger
	EventChecker ec.MultiEventChecker
}

// Policies are represented as strings, because that's how they are loaded via gRPC
type Policy string

type Label string

type SkipInfo struct {
	AgentInfo *tetragoninfo.Info
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
	Policy func(c *Conf) (Policy, error)

	// Scenarios returns a list of scenarios to test the generated policy
	Scenarios []func(c *Conf) *Scenario
}

type ScenarioRes struct {
	Name       string
	TriggerErr error
	CheckerErr error
}

func (sr *ScenarioRes) Err() error {
	var err error
	if sr.TriggerErr != nil {
		err = fmt.Errorf("trigger error: %w", sr.TriggerErr)
	}
	if sr.CheckerErr != nil {
		err = addErr(err, "checker error", sr.CheckerErr)
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
	Skipped      string // if not empty, the policy was skipped and the string contains the reason
	Err          error
	ScenariosRes []ScenarioRes
}

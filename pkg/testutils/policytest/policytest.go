// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"

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

// T defines a policy test
type T struct {
	// Name returns the name of the test
	Name string
	// Labels is a set of labels for the test
	Labels []Label

	// ShouldSkip returns true if the test is to be skipped for a certain environment
	ShouldSkip func(info *tetragoninfo.Info) bool

	// Policy generates a policy for this test
	Policy func(c *Conf) (Policy, error)

	// Scenarios returns a list of scenarios to test the generated policy
	Scenarios []func(c *Conf) *Scenario
}

type ScenarioRes struct {
	Name       string
	CheckerErr error
}

// Result of a policytest (T)
type Result struct {
	Skipped      bool
	Err          error
	ScenariosRes []ScenarioRes
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package kube contains the Kubernetes-side support for running policy tests:
// the machine-readable result schema exchanged between the in-pod runner and
// the client-side orchestrator.
package kube

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// ScenarioResult is the machine-readable result of a single policy test
// scenario. Errors are rendered as strings so the result can be serialized;
// an empty string means no error.
type ScenarioResult struct {
	Name            string `json:"name"`
	TriggerErr      string `json:"triggerErr,omitempty"`
	CheckerErr      string `json:"checkerErr,omitempty"`
	ActionCountsErr string `json:"actionCountsErr,omitempty"`
}

// TestResult is the machine-readable result of a single policy test. It mirrors
// policytest.Result with the test name attached and errors rendered as strings.
type TestResult struct {
	Name      string           `json:"name"`
	Skipped   string           `json:"skipped,omitempty"`
	Err       string           `json:"err,omitempty"`
	Scenarios []ScenarioResult `json:"scenarios,omitempty"`
}

// Failed reports whether the test did not pass. A skipped test has not failed.
func (tr TestResult) Failed() bool {
	if tr.Err != "" {
		return true
	}
	for _, s := range tr.Scenarios {
		if s.TriggerErr != "" || s.CheckerErr != "" || s.ActionCountsErr != "" {
			return true
		}
	}
	return false
}

// FromResult converts a policytest.Result for the named test into its
// serializable form.
func FromResult(name string, r *policytest.Result) TestResult {
	tr := TestResult{
		Name:    name,
		Skipped: r.Skipped,
		Err:     errString(r.Err),
	}
	for _, s := range r.ScenariosRes {
		tr.Scenarios = append(tr.Scenarios, ScenarioResult{
			Name:            s.Name,
			TriggerErr:      errString(s.TriggerErr),
			CheckerErr:      errString(s.CheckerErr),
			ActionCountsErr: errString(s.ActionCountsErr),
		})
	}
	return tr
}

// Encode serializes a set of test results for transport (e.g. via pod logs).
func Encode(results []TestResult) ([]byte, error) {
	data, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to encode results: %w", err)
	}
	return data, nil
}

// Decode parses a set of test results produced by Encode.
func Decode(data []byte) ([]TestResult, error) {
	var results []TestResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to decode results: %w", err)
	}
	return results, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

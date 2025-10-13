// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package policyfilter

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/option"
)

var (
	glblState   State
	glblError   error // nolint:errname
	setGlobalPf sync.Once
)

// GetState returns global state for policyfilter
func GetState() (State, error) {
	setGlobalPf.Do(func() {
		if option.Config.EnablePolicyFilter {
			glblError = fmt.Errorf("policyfilter is not suported in non-k8s build")
		} else {
			glblState = &disabled{}
			glblError = nil
		}
	})
	return glblState, glblError
}

// see k8s.go
func resetStateOnlyForTesting() {
	glblState = &disabled{}
	glblError = nil
}

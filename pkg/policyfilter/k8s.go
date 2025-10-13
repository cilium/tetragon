// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build k8s

package policyfilter

import (
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
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
			logger.GetLogger().Info("Enabling policy filtering")
			glblState, glblError = New(option.Config.EnablePolicyFilterCgroupMap)
		} else {
			glblState = &disabled{}
			glblError = nil
		}
	})
	return glblState, glblError
}

// ResetStateOnlyForTesting resets the global policyfilter state.
// As the name states, it should only be used for testing.
// We need this because GetState() depends on the
// option.Config.EnablePolicyFilter global and this is only initialized once.
// Callers for this should ensure that no race happens.
func resetStateOnlyForTesting() {
	if glblState != nil {
		glblState.Close()
	}
	if option.Config.EnablePolicyFilter {
		logger.GetLogger().Info("Enabling policy filtering")
		glblState, glblError = New(true)
	} else {
		glblState = &disabled{}
		glblError = nil
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package policyfilter

import (
	"sync"
)

var (
	glblState   *State
	glblError   error
	setGlobalPf sync.Once
)

// GetState returns global state for policyfilter
func GetState() (*State, error) {
	setGlobalPf.Do(func() {
		glblState, glblError = New()
	})
	return glblState, glblError
}

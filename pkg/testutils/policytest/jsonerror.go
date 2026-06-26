// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"encoding/json"
	"errors"
)

// JSONError is an error that can be marshalled in JSON a string
// Unmarshalling is also supported, but it would not maintain the original error.
type JSONError struct {
	Err error
}

func (e JSONError) Error() string {
	return e.Err.Error()
}

func (e JSONError) MarshalJSON() ([]byte, error) {
	if e.Err == nil {
		return []byte("null"), nil
	}
	return json.Marshal(e.Err.Error())
}

func (e *JSONError) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == nil || *s == "" {
		e.Err = nil
		return nil
	}
	e.Err = errors.New(*s)
	return nil
}

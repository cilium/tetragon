// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2021 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PolicyRule A policy rule including the rule labels it derives from
//
// +k8s:deepcopy-gen=true
//
// swagger:model PolicyRule
type PolicyRule struct {

	// The policy rule labels identifying the policy rules this rule derives from
	DerivedFromRules [][]string `json:"derived-from-rules"`

	// The policy rule as json
	Rule string `json:"rule,omitempty"`
}

// Validate validates this policy rule
func (m *PolicyRule) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PolicyRule) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PolicyRule) UnmarshalBinary(b []byte) error {
	var res PolicyRule
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

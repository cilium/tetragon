// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// AttachMode Core datapath attachment mode
//
// swagger:model AttachMode
type AttachMode string

func NewAttachMode(value AttachMode) *AttachMode {
	return &value
}

// Pointer returns a pointer to a freshly-allocated AttachMode.
func (m AttachMode) Pointer() *AttachMode {
	return &m
}

const (

	// AttachModeTc captures enum value "tc"
	AttachModeTc AttachMode = "tc"

	// AttachModeTcx captures enum value "tcx"
	AttachModeTcx AttachMode = "tcx"
)

// for schema
var attachModeEnum []interface{}

func init() {
	var res []AttachMode
	if err := json.Unmarshal([]byte(`["tc","tcx"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		attachModeEnum = append(attachModeEnum, v)
	}
}

func (m AttachMode) validateAttachModeEnum(path, location string, value AttachMode) error {
	if err := validate.EnumCase(path, location, value, attachModeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this attach mode
func (m AttachMode) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateAttachModeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this attach mode based on context it is used
func (m AttachMode) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

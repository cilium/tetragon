// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// EndpointBatchDeleteRequest Properties selecting a batch of endpoints to delete.
//
// swagger:model EndpointBatchDeleteRequest
type EndpointBatchDeleteRequest struct {

	// ID assigned by container runtime
	ContainerID string `json:"container-id,omitempty"`
}

// Validate validates this endpoint batch delete request
func (m *EndpointBatchDeleteRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this endpoint batch delete request based on context it is used
func (m *EndpointBatchDeleteRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EndpointBatchDeleteRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EndpointBatchDeleteRequest) UnmarshalBinary(b []byte) error {
	var res EndpointBatchDeleteRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

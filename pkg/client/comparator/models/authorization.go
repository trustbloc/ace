// Code generated by go-swagger; DO NOT EDIT.

// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Authorization An authorization object encodes the permissions granted to a third party. Its `scope` details the allowed
// action and the object on which the action will be performed. The `requestingParty` is the third party
// allowed to perform those actions.
//
// The `authToken` is an opaque tokens granting the `requestingParty` the priviledge of running a comparison
// with the document identified in `scope` at the remote Confidential Storage Hub.
//
// Example: {"requestingParty":"did:example:party_doing_comparison","scope":[{"actions":["compare"],"caveats":[{"duration":600,"type":"expiry"}],"docID":"batphone","vaultID":"did:example:123"}]}
//
// swagger:model Authorization
type Authorization struct {

	// An opaque authorization token authorizing the requesting party to perform a comparison
	// referencing the document in the `scope`.
	//
	AuthToken string `json:"authToken,omitempty"`

	// The authorization's unique ID.
	ID string `json:"id,omitempty"`

	// KeyID in the format of a DID URL that identifies the party granted authorization.
	// Required: true
	RequestingParty *string `json:"requestingParty"`

	// scope
	// Required: true
	Scope *Scope `json:"scope"`
}

// Validate validates this authorization
func (m *Authorization) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRequestingParty(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authorization) validateRequestingParty(formats strfmt.Registry) error {

	if err := validate.Required("requestingParty", "body", m.RequestingParty); err != nil {
		return err
	}

	return nil
}

func (m *Authorization) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	if m.Scope != nil {
		if err := m.Scope.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("scope")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("scope")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this authorization based on the context it is used
func (m *Authorization) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateScope(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authorization) contextValidateScope(ctx context.Context, formats strfmt.Registry) error {

	if m.Scope != nil {
		if err := m.Scope.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("scope")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("scope")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Authorization) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Authorization) UnmarshalBinary(b []byte) error {
	var res Authorization
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

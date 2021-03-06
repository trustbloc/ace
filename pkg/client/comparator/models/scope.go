// Code generated by go-swagger; DO NOT EDIT.

// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Scope scope
//
// swagger:model Scope
type Scope struct {

	// actions
	// Required: true
	Actions []string `json:"actions"`

	// auth tokens
	// Required: true
	AuthTokens *ScopeAuthTokens `json:"authTokens"`

	caveatsField []Caveat

	// Optional json path. Authorizes the comparison of a portion of the document.
	DocAttrPath string `json:"docAttrPath,omitempty"`

	// an identifier for a document stored in the Vault Server.
	// Required: true
	DocID *string `json:"docID"`

	// the Vault Server ID (DID)
	VaultID string `json:"vaultID,omitempty"`
}

// Caveats gets the caveats of this base type
func (m *Scope) Caveats() []Caveat {
	return m.caveatsField
}

// SetCaveats sets the caveats of this base type
func (m *Scope) SetCaveats(val []Caveat) {
	m.caveatsField = val
}

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *Scope) UnmarshalJSON(raw []byte) error {
	var data struct {
		Actions []string `json:"actions"`

		AuthTokens *ScopeAuthTokens `json:"authTokens"`

		Caveats json.RawMessage `json:"caveats"`

		DocAttrPath string `json:"docAttrPath,omitempty"`

		DocID *string `json:"docID"`

		VaultID string `json:"vaultID,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var propCaveats []Caveat
	if string(data.Caveats) != "null" {
		caveats, err := UnmarshalCaveatSlice(bytes.NewBuffer(data.Caveats), runtime.JSONConsumer())
		if err != nil && err != io.EOF {
			return err
		}
		propCaveats = caveats
	}

	var result Scope

	// actions
	result.Actions = data.Actions

	// authTokens
	result.AuthTokens = data.AuthTokens

	// caveats
	result.caveatsField = propCaveats

	// docAttrPath
	result.DocAttrPath = data.DocAttrPath

	// docID
	result.DocID = data.DocID

	// vaultID
	result.VaultID = data.VaultID

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m Scope) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {
		Actions []string `json:"actions"`

		AuthTokens *ScopeAuthTokens `json:"authTokens"`

		DocAttrPath string `json:"docAttrPath,omitempty"`

		DocID *string `json:"docID"`

		VaultID string `json:"vaultID,omitempty"`
	}{

		Actions: m.Actions,

		AuthTokens: m.AuthTokens,

		DocAttrPath: m.DocAttrPath,

		DocID: m.DocID,

		VaultID: m.VaultID,
	})
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		Caveats []Caveat `json:"caveats"`
	}{

		Caveats: m.caveatsField,
	})
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this scope
func (m *Scope) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthTokens(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCaveats(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDocID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var scopeActionsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["compare"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		scopeActionsItemsEnum = append(scopeActionsItemsEnum, v)
	}
}

func (m *Scope) validateActionsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, scopeActionsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Scope) validateActions(formats strfmt.Registry) error {

	if err := validate.Required("actions", "body", m.Actions); err != nil {
		return err
	}

	for i := 0; i < len(m.Actions); i++ {

		// value enum
		if err := m.validateActionsItemsEnum("actions"+"."+strconv.Itoa(i), "body", m.Actions[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *Scope) validateAuthTokens(formats strfmt.Registry) error {

	if err := validate.Required("authTokens", "body", m.AuthTokens); err != nil {
		return err
	}

	if m.AuthTokens != nil {
		if err := m.AuthTokens.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authTokens")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authTokens")
			}
			return err
		}
	}

	return nil
}

func (m *Scope) validateCaveats(formats strfmt.Registry) error {
	if swag.IsZero(m.Caveats()) { // not required
		return nil
	}

	for i := 0; i < len(m.Caveats()); i++ {

		if err := m.caveatsField[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("caveats" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("caveats" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *Scope) validateDocID(formats strfmt.Registry) error {

	if err := validate.Required("docID", "body", m.DocID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this scope based on the context it is used
func (m *Scope) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthTokens(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCaveats(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Scope) contextValidateAuthTokens(ctx context.Context, formats strfmt.Registry) error {

	if m.AuthTokens != nil {
		if err := m.AuthTokens.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authTokens")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authTokens")
			}
			return err
		}
	}

	return nil
}

func (m *Scope) contextValidateCaveats(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Caveats()); i++ {

		if err := m.caveatsField[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("caveats" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("caveats" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Scope) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Scope) UnmarshalBinary(b []byte) error {
	var res Scope
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// ScopeAuthTokens scope auth tokens
//
// swagger:model ScopeAuthTokens
type ScopeAuthTokens struct {

	// edv
	Edv string `json:"edv,omitempty"`

	// kms
	Kms string `json:"kms,omitempty"`
}

// Validate validates this scope auth tokens
func (m *ScopeAuthTokens) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this scope auth tokens based on context it is used
func (m *ScopeAuthTokens) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ScopeAuthTokens) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScopeAuthTokens) UnmarshalBinary(b []byte) error {
	var res ScopeAuthTokens
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

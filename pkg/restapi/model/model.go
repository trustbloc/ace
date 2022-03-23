/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "time"

// UNIRegistrar uni-registrar.
type UNIRegistrar struct {
	DriverURL string            `json:"driverURL,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// ErrorResponse to send error message in the response.
type ErrorResponse struct {
	// error message
	Message string `json:"errMessage,omitempty"`
}

// DataProfile struct for profile.
type DataProfile struct {
	Name                    string     `json:"name,omitempty"`
	DID                     string     `json:"did,omitempty"`
	URI                     string     `json:"uri,omitempty"`
	SignatureType           string     `json:"signatureType,omitempty"`
	SignatureRepresentation int        `json:"signatureRepresentation,omitempty"`
	Creator                 string     `json:"creator,omitempty"`
	Created                 *time.Time `json:"created,omitempty"`
	DIDPrivateKey           string     `json:"didPrivateKey,omitempty"`
}

// ProtectedData defines the model for protected data.
type ProtectedData struct {
	Data          string `json:"data"`
	PolicyID      string `json:"policyId"`
	Hash          string `json:"hash"`
	DID           string `json:"did"`
	TargetVCDocID string `json:"targetVCDocID"`
}

// PolicyDocument contains a policy configuration for storing and releasing protected data.
type PolicyDocument struct {
	// A list of DIDs identifying the entities collecting sensitive data and permitted to protect those objects with
	// this policy.
	Collectors []string `json:"collectors"`
	// A list of DIDs identifying the entities permitted to request the release of protected objects associated with
	// this policy.
	Handlers []string `json:"handlers"`
	// A list of DIDs identifying entities required to provide authorization for the release of the protected object.
	Approvers []string `json:"approvers"`
	// The minimum number of (unique) approvers required before an object may be released back to the handler.
	// This allows for an "m of N" approval scenario. Constraints: 0 < min_approvers < approvers.length.
	MinApprovers int `json:"min_approvers"`
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

// Policy contains policy configuration for storing and releasing protected data.
type Policy struct {
	// Policy ID.
	ID string `json:"id"`
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

// Role is a role of entity represented by DID.
type Role int

const (
	// Collector represents an entity that collects sensitive data.
	Collector Role = iota
	// Handler represents an entity that is permitted to request the release of protected data.
	Handler
	// Approver represents an entity that provides authorization for the release of the protected data.
	Approver
)

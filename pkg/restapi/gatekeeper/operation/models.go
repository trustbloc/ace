/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// ProtectRequest is a request to protect Target using policy with ID Policy.
type ProtectRequest struct {
	Policy string `json:"policy"`
	Target string `json:"target"`
}

// ProtectResponse is a response for ProtectRequest.
type ProtectResponse struct {
	DID string `json:"did"`
}

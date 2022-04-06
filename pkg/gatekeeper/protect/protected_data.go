/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protect

// ProtectedData defines the model for protected data.
type ProtectedData struct {
	DID      string `json:"did"`
	VCDocID  string `json:"vc_doc_id"`
	PolicyID string `json:"policy_id"`
}

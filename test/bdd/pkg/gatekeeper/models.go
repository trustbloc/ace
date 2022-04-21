/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

type protectReq struct {
	Policy string `json:"policy"`
	Target string `json:"target"`
}

type protectResp struct {
	DID string `json:"did"`
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

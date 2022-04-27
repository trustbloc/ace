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

// ReleaseRequest is a request to create release transaction on a DID.
type ReleaseRequest struct {
	DID string `json:"did"`
}

// ReleaseResponse is a response for ReleaseRequest.
type ReleaseResponse struct {
	TicketID string `json:"ticket_id"`
}

// TicketStatusResponse is a response with status of the ticket.
type TicketStatusResponse struct {
	Status string `json:"status"`
}

// CollectResponse is a response for collect api.
type CollectResponse struct {
	QueryID string `json:"query_id"`
}

// ExtractRequest is a response for ReleaseRequest.
type ExtractRequest struct {
	QueryID string `json:"query_id"`
}

// ExtractResponse is a response for ExtractRequest.
type ExtractResponse struct {
	Target string `json:"target"`
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// createPolicyReq model
//
// swagger:parameters createPolicyReq
type createPolicyReq struct { //nolint:unused,deadcode
	// Policy ID.
	//
	// in: path
	// required: true
	PolicyID string `json:"policy_id"`

	// in: body
	Body struct {
		Collectors   []string `json:"collectors"`
		Handlers     []string `json:"handlers"`
		Approvers    []string `json:"approvers"`
		MinApprovers int      `json:"min_approvers"`
	}
}

// createPolicyResp model
//
// swagger:response createPolicyResp
type createPolicyResp struct{} //nolint:unused,deadcode

// protectReq model
//
// swagger:parameters protectReq
type protectReq struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ProtectRequest
	}
}

// protectResp model
//
// swagger:response protectResp
type protectResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ProtectResponse
	}
}

// releaseReq model
//
// swagger:parameters releaseReq
type releaseReq struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ReleaseRequest
	}
}

// releaseResp model
//
// swagger:response releaseResp
type releaseResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ReleaseResponse
	}
}

// authorizeReq model
//
// swagger:parameters authorizeReq
type authorizeReq struct { //nolint:unused,deadcode
	// Ticket ID.
	//
	// in: path
	// required: true
	TicketID string `json:"ticket_id"`
}

// authorizeResp model
//
// swagger:response authorizeResp
type authorizeResp struct{} //nolint:unused,deadcode

// ticketStatusReq model
//
// swagger:parameters ticketStatusReq
type ticketStatusReq struct { //nolint:unused,deadcode
	// Ticket ID.
	//
	// in: path
	// required: true
	TicketID string `json:"ticket_id"`
}

// ticketStatusResp model
//
// swagger:response ticketStatusResp
type ticketStatusResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		TicketStatusResponse
	}
}

// collectReq model
//
// swagger:parameters collectReq
type collectReq struct { //nolint:unused,deadcode
	// Ticket ID.
	//
	// in: path
	// required: true
	TicketID string `json:"ticket_id"`
}

// collectResp model
//
// swagger:response collectResp
type collectResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		CollectResponse
	}
}

// extractReq model
//
// swagger:parameters extractReq
type extractReq struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ExtractRequest
	}
}

// extractResp model
//
// swagger:response extractResp
type extractResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		ExtractResponse
	}
}

// errorResp model
//
// swagger:response errorResp
type errorResp struct { //nolint:unused,deadcode
	// The error message
	//
	// in: body
	Body struct {
		Message string `json:"errMessage,omitempty"`
	}
}

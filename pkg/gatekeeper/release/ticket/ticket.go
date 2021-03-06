/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ticket

// Status is a ticket release status.
type Status int

const (
	// New represents a new ticket.
	New Status = iota
	// Collecting represents a ticket that is collecting approvals.
	Collecting
	// ReadyToCollect represents a ticket ready to collect.
	ReadyToCollect
)

// String returns string representation of Status.
func (s Status) String() string {
	switch s {
	case New:
		return "NEW"
	case Collecting:
		return "COLLECTING"
	case ReadyToCollect:
		return "READY_TO_COLLECT"
	default:
		return ""
	}
}

// Ticket represents a ticket to release protected resource (DID).
type Ticket struct {
	ID         string   `json:"id"`
	DID        string   `json:"did"`
	Status     Status   `json:"status"`
	ApprovedBy []string `json:"approved_by"`
}

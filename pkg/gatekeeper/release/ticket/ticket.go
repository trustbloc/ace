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

// Ticket represents a ticket to release protected resource (DID).
type Ticket struct {
	ID     string `json:"id"`
	DID    string `json:"did"`
	Status Status `json:"status"`
}

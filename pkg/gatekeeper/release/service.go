/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package release

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package release_test -source=service.go -mock_names policyService=MockPolicyService,protectService=MockProtectService

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
)

const storeName = "ticket"

type policyService interface {
	Get(ctx context.Context, policyID string) (*policy.Policy, error)
}

type protectService interface {
	Get(ctx context.Context, did string) (*protect.ProtectedData, error)
}

// Config defines dependencies for a service.
type Config struct {
	StoreProvider  storage.Provider
	PolicyService  policyService
	ProtectService protectService
}

// Service is a service for releasing protected resources.
type Service struct {
	store          storage.Store
	policyService  policyService
	protectService protectService
}

// NewService returns a new instance of Service.
func NewService(config *Config) (*Service, error) {
	store, err := config.StoreProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open ticket store: %w", err)
	}

	return &Service{
		store:          store,
		policyService:  config.PolicyService,
		protectService: config.ProtectService,
	}, nil
}

// Release creates release transaction (ticket) on the protected resource (DID).
func (s *Service) Release(_ context.Context, did string) (*ticket.Ticket, error) {
	t := &ticket.Ticket{
		ID:     uuid.New().String(),
		DID:    did,
		Status: ticket.New,
	}

	b, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	if err = s.store.Put(t.ID, b); err != nil {
		return nil, fmt.Errorf("store ticket: %w", err)
	}

	return t, nil
}

// Get retrieves ticket from the underlying storage by ID.
func (s *Service) Get(_ context.Context, ticketID string) (*ticket.Ticket, error) {
	b, err := s.store.Get(ticketID)
	if err != nil {
		return nil, fmt.Errorf("get ticket: %w", err)
	}

	var t ticket.Ticket

	if err = json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("unmarshal ticket: %w", err)
	}

	return &t, nil
}

// Authorize authorizes ticket by approver.
func (s *Service) Authorize(ctx context.Context, ticketID, approver string) error {
	t, err := s.Get(ctx, ticketID)
	if err != nil {
		return fmt.Errorf("get ticket to authorize: %w", err)
	}

	data, err := s.protectService.Get(ctx, t.DID)
	if err != nil {
		return fmt.Errorf("get protected data: %w", err)
	}

	p, err := s.policyService.Get(ctx, data.PolicyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	for _, a := range p.Approvers {
		if a == approver {
			approved := false

			for _, b := range t.ApprovedBy {
				if b == approver {
					approved = true

					break
				}
			}

			if !approved {
				t.ApprovedBy = append(t.ApprovedBy, approver)
			}
		}
	}

	if len(t.ApprovedBy) < p.MinApprovers {
		t.Status = ticket.Collecting
	} else {
		t.Status = ticket.ReadyToCollect
	}

	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal ticket: %w", err)
	}

	if err = s.store.Put(t.ID, b); err != nil {
		return fmt.Errorf("update ticket: %w", err)
	}

	return nil
}

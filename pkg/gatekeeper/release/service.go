/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package release

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
)

const storeName = "ticket"

// Service is a service for releasing protected resources.
type Service struct {
	store storage.Store
}

// NewService returns a new instance of Service.
func NewService(storeProvider storage.Provider) (*Service, error) {
	store, err := storeProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open ticket store: %w", err)
	}

	return &Service{
		store: store,
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

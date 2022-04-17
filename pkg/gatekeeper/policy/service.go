/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	storeName = "policy"
)

// ErrNotAllowed is returned when a subject DID is not allowed to proceed under the given policy.
var ErrNotAllowed = errors.New("not allowed")

// Service works with policy configurations.
type Service struct {
	store storage.Store
}

// NewService returns a new instance of Service.
func NewService(storeProvider storage.Provider) (*Service, error) {
	store, err := storeProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open policy store: %w", err)
	}

	return &Service{store: store}, nil
}

// Save stores policy configuration.
func (s *Service) Save(_ context.Context, doc *Policy) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err = s.store.Put(doc.ID, b); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}

	return nil
}

// Check checks if DID is allowed to proceed under the given policy.
func (s *Service) Check(_ context.Context, policyID, did string, role Role) error {
	b, err := s.store.Get(policyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	var policy Policy

	if err = json.Unmarshal(b, &policy); err != nil {
		return fmt.Errorf("unmarshal policy: %w", err)
	}

	switch role {
	case Collector:
		for _, c := range policy.Collectors {
			if c == did {
				return nil
			}
		}
	case Handler:
		for _, h := range policy.Handlers {
			if h == did {
				return nil
			}
		}
	case Approver:
		for _, a := range policy.Approvers {
			if a == did {
				return nil
			}
		}
	}

	return ErrNotAllowed
}

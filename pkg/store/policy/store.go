/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/restapi/model"
)

const (
	storeName = "policy"
)

// Repository defines the repository for policy configurations.
type Repository interface {
	Put(policyID string, doc *model.PolicyDocument) error
}

// Store is a store for policy configurations.
type Store struct {
	store storage.Store
}

// New returns a new instance of Store.
func New(storageProvider storage.Provider) (*Store, error) {
	store, err := storageProvider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &Store{store: store}, nil
}

// Put stores policy document.
func (s *Store) Put(policyID string, doc *model.PolicyDocument) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal policy document: %w", err)
	}

	if err = s.store.Put(policyID, b); err != nil {
		return fmt.Errorf("put policy document: %w", err)
	}

	return nil
}

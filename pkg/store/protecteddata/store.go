/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protecteddata

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/restapi/model"
)

const (
	storeName = "protected_data_"
)

// Storage defines the interface to work with protected data.
type Storage interface {
	Get(hash string) (*model.ProtectedData, error)
	Put(data *model.ProtectedData) error
}

// Store is a store for protected data.
type Store struct {
	store storage.Store
}

// New returns a new instance of protected data store.
func New(storageProvider storage.Provider) (*Store, error) {
	store, err := storageProvider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &Store{store: store}, nil
}

// Get gets protected data by hash.
func (s *Store) Get(hash string) (*model.ProtectedData, error) {
	data, err := s.store.Get(hash)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("sensitive data repository get: storage get: %w", err)
	}

	sd := &model.ProtectedData{}

	err = json.Unmarshal(data, sd)
	if err != nil {
		return nil, fmt.Errorf("sensitive data repository get: unmarshal: %w", err)
	}

	return sd, nil
}

// Put saves protected data.
func (s *Store) Put(data *model.ProtectedData) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal protected data: %w", err)
	}

	err = s.store.Put(data.Hash, bytes)
	if err != nil {
		return fmt.Errorf("put protected data: %w", err)
	}

	return nil
}

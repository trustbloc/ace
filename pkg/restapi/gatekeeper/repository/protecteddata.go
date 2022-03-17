/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package repository

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	storeName = "protected_data_"
)

// ProtectedData defines the model sensitive data.
type ProtectedData struct {
	Data          string `json:"data"`
	PolicyID      string `json:"policyId"`
	Hash          string `json:"hash"`
	DID           string `json:"did"`
	TargetVCDocID string `json:"targetVCDocID"`
}

// ProtectedDataRepository defines the interface to work with sensitive data.
type ProtectedDataRepository interface {
	Get(hash string) (*ProtectedData, error)
	Put(data *ProtectedData) error
}

type protectedDataRepository struct {
	store storage.Store
}

// NewProtectedDataRepository creates new ProtectedDataRepository.
func NewProtectedDataRepository(storeProvider storage.Provider) (ProtectedDataRepository, error) {
	store, err := storeProvider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &protectedDataRepository{store: store}, nil
}

func (s *protectedDataRepository) Get(hash string) (*ProtectedData, error) {
	data, err := s.store.Get(hash)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("sensitive data repository get: storage get: %w", err)
	}

	sd := &ProtectedData{}

	err = json.Unmarshal(data, sd)
	if err != nil {
		return nil, fmt.Errorf("sensitive data repository get: unmarshal: %w", err)
	}

	return sd, nil
}

func (s *protectedDataRepository) Put(data *ProtectedData) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("sensitive data repository put: marshal: %w", err)
	}

	err = s.store.Put(data.Hash, bytes)
	if err != nil {
		return fmt.Errorf("sensitive data repository put: storage put: %w", err)
	}

	return nil
}

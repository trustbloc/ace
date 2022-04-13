/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
)

const testPolicy = `{
  "id": "test-policy",
  "collectors": [
    "did:example:ray_stantz"
  ],
  "handlers": [
    "did:example:alter_peck"
  ],
  "approvers": [
    "did:example:peter_venkman",
    "did:example:eon_spengler",
    "did:example:winton_zeddemore"
  ],
  "min_approvers": 2
}`

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := policy.NewService(storage.NewMockStoreProvider())

		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.ErrOpenStoreHandle = errors.New("open error")

		svc, err := policy.NewService(store)

		require.EqualError(t, err, "open policy store: open error")
		require.Nil(t, svc)
	})
}

func TestService_Get(t *testing.T) {
	const policyID = "test-policy"

	t.Run("Success", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.Store[policyID] = storage.DBEntry{
			Value: []byte(testPolicy),
		}

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		p, err := svc.Get(policyID)

		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("Fail to get policy", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrGet = errors.New("get error")

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		p, err := svc.Get(policyID)

		require.EqualError(t, err, "get policy: get error")
		require.Nil(t, p)
	})
}

func TestService_Save(t *testing.T) {
	var p policy.Policy

	require.NoError(t, json.Unmarshal([]byte(testPolicy), &p))

	t.Run("Success", func(t *testing.T) {
		svc, err := policy.NewService(storage.NewMockStoreProvider())
		require.NoError(t, err)

		err = svc.Save(&p)

		require.NoError(t, err)
	})

	t.Run("Fail to save policy", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("put error")

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		err = svc.Save(&p)

		require.EqualError(t, err, "save policy: put error")
	})
}

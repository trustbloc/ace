/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestService_Save(t *testing.T) {
	var p policy.Policy

	require.NoError(t, json.Unmarshal([]byte(testPolicy), &p))

	t.Run("Success", func(t *testing.T) {
		svc, err := policy.NewService(storage.NewMockStoreProvider())
		require.NoError(t, err)

		err = svc.Save(context.Background(), &p)

		require.NoError(t, err)
	})

	t.Run("Fail to save policy", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("put error")

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		err = svc.Save(context.Background(), &p)

		require.EqualError(t, err, "save policy: put error")
	})
}

func TestService_Check(t *testing.T) {
	const (
		testDID      = "did:example:test"
		testPolicyID = "test-policy"
	)

	t.Run("Fail to get policy", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrGet = errors.New("get error")

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		err = svc.Check(context.Background(), testPolicyID, testDID, policy.Collector)

		require.EqualError(t, err, "get policy: get error")
	})

	t.Run("Fail to unmarshal policy", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.Store[testPolicyID] = storage.DBEntry{Value: []byte("invalid policy")}

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		err = svc.Check(context.Background(), testPolicyID, testDID, policy.Collector)

		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal policy")
	})

	t.Run("ErrNotAllowed", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.Store[testPolicyID] = storage.DBEntry{Value: []byte(testPolicy)}

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		tests := []struct {
			did  string
			role policy.Role
		}{
			{"did:example:eon_spengler", policy.Collector},
			{"did:example:peter_venkman", policy.Handler},
			{"did:example:ray_stantz", policy.Approver},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("role_%d", tt.role), func(t *testing.T) {
				err = svc.Check(context.Background(), testPolicyID, tt.did, tt.role)

				require.EqualError(t, err, policy.ErrNotAllowed.Error())
			})
		}
	})

	t.Run("Success", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.Store[testPolicyID] = storage.DBEntry{Value: []byte(testPolicy)}

		svc, err := policy.NewService(store)
		require.NoError(t, err)

		tests := []struct {
			did  string
			role policy.Role
		}{
			{"did:example:ray_stantz", policy.Collector},
			{"did:example:alter_peck", policy.Handler},
			{"did:example:eon_spengler", policy.Approver},
		}

		for _, tt := range tests {
			t.Run("", func(t *testing.T) {
				err = svc.Check(context.Background(), testPolicyID, tt.did, tt.role)

				require.NoError(t, err)
			})
		}
	})
}

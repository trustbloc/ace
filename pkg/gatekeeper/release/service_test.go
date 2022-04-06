/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package release_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/release"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := release.NewService(storage.NewMockStoreProvider())

		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.ErrOpenStoreHandle = errors.New("open error")

		svc, err := release.NewService(store)

		require.EqualError(t, err, "open ticket store: open error")
		require.Nil(t, svc)
	})
}

func TestService_Release(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := release.NewService(storage.NewMockStoreProvider())
		require.NoError(t, err)

		ticket, err := svc.Release(context.Background(), "did:example:test")

		require.NoError(t, err)
		require.NotNil(t, ticket)
	})

	t.Run("Fail to store ticket", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("put error")

		svc, err := release.NewService(store)
		require.NoError(t, err)

		ticket, err := svc.Release(context.Background(), "did:example:test")

		require.EqualError(t, err, "store ticket: put error")
		require.Nil(t, ticket)
	})
}

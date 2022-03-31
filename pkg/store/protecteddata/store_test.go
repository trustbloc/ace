/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protecteddata_test

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/model"
	"github.com/trustbloc/ace/pkg/store/protecteddata"
)

func TestOpenStoreSuccess(t *testing.T) {
	storeProvider := mem.NewProvider()

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestStoreItemNotFound(t *testing.T) {
	storeProvider := mem.NewProvider()

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)

	item, err := store.Get("test")

	require.NoError(t, err)
	require.Nil(t, item)
}

func TestStoreItemFound(t *testing.T) {
	storeProvider := mem.NewProvider()

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Put(&model.ProtectedData{
		Hash: "test",
	})

	require.NoError(t, err)

	item, err := store.Get("test")

	require.NoError(t, err)
	require.NotNil(t, item)
}

func TestStoreSavedProperly(t *testing.T) {
	storeProvider := mem.NewProvider()

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Put(&model.ProtectedData{
		PolicyID:      "2",
		Hash:          "test",
		DID:           "3",
		TargetVCDocID: "4",
	})

	require.NoError(t, err)

	item, err := store.Get("test")

	require.NoError(t, err)
	require.NotNil(t, item)

	require.Equal(t, item.PolicyID, "2")
	require.Equal(t, item.Hash, "test")
	require.Equal(t, item.DID, "3")
	require.Equal(t, item.TargetVCDocID, "4")
}

func TestUnderlyingStoreOpenFailing(t *testing.T) {
	storeProvider := &mockstorage.MockStoreProvider{ErrOpenStoreHandle: errors.New("open failed")}

	_, err := protecteddata.New(storeProvider)
	require.Error(t, err)
}

func TestUnderlyingStoreGetFailing(t *testing.T) {
	storeProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		ErrGet: errors.New("get failed"),
	}}

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = store.Get("test")

	require.Error(t, err)
}

func TestUnderlyingStorePutFailing(t *testing.T) {
	storeProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		ErrPut: errors.New("put failed"),
	}}

	store, err := protecteddata.New(storeProvider)

	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Put(&model.ProtectedData{
		Hash: "test",
	})

	require.Error(t, err)
}

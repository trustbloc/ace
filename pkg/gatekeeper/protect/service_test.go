/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protect_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

func TestProtect_StoreGetFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	store.Store.ErrGet = errors.New("store get error")

	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	_, err = svc.Protect(context.Background(), "test data", "policyID")
	require.Contains(t, err.Error(), "store get error")
}

func TestProtect_StoreGetExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()

	testData, err := json.Marshal(&protect.ProtectedData{DID: "test did"})
	require.NoError(t, err)

	hash, err := calculateHash("test data")
	require.NoError(t, err)

	store.Store.Store[hash] = storage.DBEntry{Value: testData}

	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	protectedData, err := svc.Protect(context.Background(), "test data", "policyID")

	require.NoError(t, err)
	require.Equal(t, protectedData.DID, "test did")
}

func calculateHash(data string) (string, error) {
	h := fnv.New128()

	if _, err := h.Write([]byte(data)); err != nil {
		return "", fmt.Errorf("calculate data hash: %w", err)
	}

	return string(h.Sum(nil)), nil
}

func TestProtect_CreateVaultFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(nil, errors.New("create vaultClient failed"))

	_, err = svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "create vaultClient failed")
}

func TestProtect_WrapVcFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(nil, errors.New("issues credential failed"))

	_, err = svc.Protect(context.Background(), "test data", "policyID")

	require.EqualError(t, err, "wrap data into vc: issues credential failed")
}

func TestProtect_DidDoesNotExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(&verifiable.Credential{}, nil)

	vdr.EXPECT().Resolve("did:orb:test").Return(nil, errors.New("DID does not exist")).Times(10)

	_, err = svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "DID does not exist")
}

func TestProtect_SaveDocFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, errors.New("save doc failed"))

	_, err = svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "save doc failed")
}

func TestProtect_StorePutFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	store.Store.ErrPut = errors.New("store put error")

	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	_, err = svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "store put error")
}

func TestProtect_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMockStoreProvider()
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDR(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc, err := protect.NewService(&protect.Config{
		StoreProvider: store,
		VaultClient:   vaultClient,
		VDR:           vdr,
		VCIssuer:      vcIssuer,
	})
	require.NoError(t, err)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	protectedData, err := svc.Protect(context.Background(), "test data", "policyID")

	require.Nil(t, err)
	require.Equal(t, protectedData.DID, "did:orb:vault")
}

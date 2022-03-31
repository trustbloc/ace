/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/protect"
	"github.com/trustbloc/ace/pkg/restapi/model"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

func TestProtect_StoreGetFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, errors.New("store get error"))

	_, err := svc.Protect(context.Background(), "test data", "policyID")
	require.EqualError(t, err, "store get error")
}

func TestProtect_StoreGetExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(&model.ProtectedData{
		DID: "test did",
	}, nil)

	did, err := svc.Protect(context.Background(), "test data", "policyID")

	require.NoError(t, err)
	require.Equal(t, did, "test did")
}

func TestProtect_CreateVaultFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(nil, errors.New("create vaultClient failed"))

	_, err := svc.Protect(context.Background(), "test data", "policyID")

	require.EqualError(t, err, "create vaultClient failed")
}

func TestProtect_WrapVcFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(nil, errors.New("issues credential failed"))

	_, err := svc.Protect(context.Background(), "test data", "policyID")

	require.EqualError(t, err, "wrap data into vc: issues credential failed")
}

func TestProtect_DidDoesNotExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(&verifiable.Credential{}, nil)

	vdr.EXPECT().Resolve("did:orb:test").Return(nil, errors.New("DID does not exist")).Times(10)

	_, err := svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "DID does not exist")
}

func TestProtect_SaveDocFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, errors.New("save doc failed"))

	_, err := svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "save doc failed")
}

func TestProtect_StorePutFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	store.EXPECT().Put(gomock.Any()).Return(errors.New("store put error"))

	_, err := svc.Protect(context.Background(), "test data", "policyID")

	require.Contains(t, err.Error(), "store put error")
}

func TestProtect_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdr := NewMockVDRRegistry(ctrl)
	vcIssuer := NewMockVCIssuer(ctrl)

	svc := protect.NewService(&protect.Config{
		Store:       store,
		VaultClient: vaultClient,
		VDR:         vdr,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any(), gomock.Any()).Return(vc, nil)

	vdr.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	store.EXPECT().Put(gomock.Any()).DoAndReturn(func(data *model.ProtectedData) error {
		require.Equal(t, data.PolicyID, "policyID")

		return nil
	})

	did, err := svc.Protect(context.Background(), "test data", "policyID")

	require.Nil(t, err)
	require.Equal(t, did, "did:orb:vault")
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protectop_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/protectop"
	"github.com/trustbloc/ace/pkg/restapi/model"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

func TestProtectOp_StoreGetFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, errors.New("store get error"))

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.EqualError(t, err, "store get error")
}

func TestProtectOp_StoreGetExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(&model.ProtectedData{
		DID: "test did",
	}, nil)

	resp, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, resp.Did, "test did")
}

func TestProtectOp_CreateVaultFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(nil, errors.New("create vaultClient failed"))

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.EqualError(t, err, "create vaultClient failed")
}

func TestProtectOp_WrapVcFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any()).Return(nil, errors.New("issues credential failed"))

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.EqualError(t, err, "wrap data into vc: issues credential failed")
}

func TestProtectOp_DidDoesNotExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:test",
	}, nil)

	vcIssuer.EXPECT().IssueCredential(gomock.Any()).Return(&verifiable.Credential{}, nil)

	vdri.EXPECT().Resolve("did:orb:test").Return(nil, errors.New("DID does not exist")).Times(10)

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.Contains(t, err.Error(), "DID does not exist")
}

func TestProtectOp_SaveDocFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any()).Return(vc, nil)

	vdri.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, errors.New("save doc failed"))

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.Contains(t, err.Error(), "save doc failed")
}

func TestProtectOp_StorePutFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any()).Return(vc, nil)

	vdri.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	store.EXPECT().Put(gomock.Any()).Return(errors.New("store put error"))

	_, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.Contains(t, err.Error(), "store put error")
}

func TestProtectOp_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := NewMockProtectedDataStore(ctrl)
	vaultClient := NewMockVault(ctrl)
	vdri := NewMockVDRIRegistry(ctrl)
	vcIssuer := NewMockvcIssuer(ctrl)

	op := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       store,
		VaultClient: vaultClient,
		VDRI:        vdri,
		VCIssuer:    vcIssuer,
	})

	store.EXPECT().Get(gomock.Any()).Return(nil, nil)

	vaultClient.EXPECT().CreateVault().Return(&vault.CreatedVault{
		ID: "did:orb:vault",
	}, nil)

	vc := &verifiable.Credential{}

	vcIssuer.EXPECT().IssueCredential(gomock.Any()).Return(vc, nil)

	vdri.EXPECT().Resolve("did:orb:vault").Return(nil, nil)

	vaultClient.EXPECT().SaveDoc("did:orb:vault", gomock.Any(), vc).Return(nil, nil)

	store.EXPECT().Put(gomock.Any()).DoAndReturn(func(data *model.ProtectedData) error {
		require.Equal(t, data.PolicyID, "10")

		return nil
	})

	resp, err := op.ProtectOp(&models.ProtectReq{
		Policy: "10",
		Target: "test data",
	})

	require.Nil(t, err)
	require.Equal(t, resp.Did, "did:orb:vault")
}

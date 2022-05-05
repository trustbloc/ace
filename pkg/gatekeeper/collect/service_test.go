/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collect_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	"github.com/trustbloc/ace/pkg/gatekeeper/collect"
	"github.com/trustbloc/ace/pkg/gatekeeper/config"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

func TestCollect_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := NewMockConfigService(ctrl)
	cshService := NewMockCSHClient(ctrl)
	vaultClient := NewMockVault(ctrl)

	cfgService.EXPECT().Get().Return(
		&config.Config{
			CSHPubKeyURL: "did:orb:csh123456#122344",
		}, nil)

	cshService.EXPECT().PostHubstoreProfilesProfileIDQueries(gomock.Any()).Return(
		&operations.PostHubstoreProfilesProfileIDQueriesCreated{
			Location: "http://csh-domin/profle/1/queries/query1234",
		}, nil)

	vaultClient.EXPECT().CreateAuthorization(
		"did:orb:vault12345", "did:orb:csh123456#122344", gomock.Any()).Return(
		&vault.CreatedAuthorization{
			Tokens: &vault.Tokens{
				EDV: "edv-token",
				KMS: "kms-token",
			},
		},
		nil,
	)

	vaultClient.EXPECT().GetDocMetaData("did:orb:vault12345", "did:orb:vc12345").Return(
		&vault.DocumentMetadata{
			ID:        "did:orb:vault12345",
			URI:       "https://edv/vaultId/doc/docID",
			EncKeyURI: "https://kms/keystores/storeId/key/keyId",
		},
		nil,
	)

	srv := collect.NewService(cfgService, vaultClient, cshService)

	auth, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID:     "did:orb:vault12345",
		VCDocID: "did:orb:vc12345",
	}, "did:orb:rp123456")

	require.NoError(t, err)
	require.Equal(t, "query1234", auth)
}

func TestCollect_BadConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := NewMockConfigService(ctrl)
	cshService := NewMockCSHClient(ctrl)
	vaultClient := NewMockVault(ctrl)

	cfgService.EXPECT().Get().Return(nil, errors.New("bad config"))

	srv := collect.NewService(cfgService, vaultClient, cshService)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "bad config")
}

func TestCollect_BadAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := NewMockConfigService(ctrl)
	cshService := NewMockCSHClient(ctrl)
	vaultClient := NewMockVault(ctrl)

	cfgService.EXPECT().Get().Return(
		&config.Config{
			CSHPubKeyURL: "did:orb:csh123456#122344",
		}, nil)

	vaultClient.EXPECT().CreateAuthorization(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, errors.New("create authorization failed"))

	srv := collect.NewService(cfgService, vaultClient, cshService)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "create authorization failed")
}

func TestCollect_PostAuthorizationFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := NewMockConfigService(ctrl)
	cshService := NewMockCSHClient(ctrl)
	vaultClient := NewMockVault(ctrl)

	cfgService.EXPECT().Get().Return(
		&config.Config{
			CSHPubKeyURL: "did:orb:csh123456#122344",
		}, nil)

	cshService.EXPECT().PostHubstoreProfilesProfileIDQueries(gomock.Any()).
		Return(nil, errors.New("post authorization failed"))

	vaultClient.EXPECT().CreateAuthorization(
		"did:orb:vault12345", "did:orb:csh123456#122344", gomock.Any()).Return(
		&vault.CreatedAuthorization{
			Tokens: &vault.Tokens{
				EDV: "edv-token",
				KMS: "kms-token",
			},
		},
		nil,
	)

	vaultClient.EXPECT().GetDocMetaData("did:orb:vault12345", "did:orb:vc12345").Return(
		&vault.DocumentMetadata{
			ID:        "did:orb:vault12345",
			URI:       "https://edv/vaultId/doc/docID",
			EncKeyURI: "https://kms/keystores/storeId/key/keyId",
		},
		nil,
	)

	srv := collect.NewService(cfgService, vaultClient, cshService)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID:     "did:orb:vault12345",
		VCDocID: "did:orb:vc12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "post authorization failed")
}

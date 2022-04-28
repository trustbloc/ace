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

	"github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodel "github.com/trustbloc/ace/pkg/client/comparator/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/collect"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

func TestCollect_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	vaultClient := NewMockVault(ctrl)

	comparator.EXPECT().GetConfig(gomock.Any()).Return(&operations.GetConfigOK{
		Payload: &compmodel.Config{
			AuthKeyURL: "did:orb:comparator123456",
		},
	}, nil)

	comparator.EXPECT().PostAuthorizations(gomock.Any()).Return(&operations.PostAuthorizationsOK{
		Payload: &compmodel.Authorization{
			AuthToken: "auth-token",
		},
	}, nil)

	vaultClient.EXPECT().CreateAuthorization(
		"did:orb:vault12345", "did:orb:comparator123456", gomock.Any()).Return(
		&vault.CreatedAuthorization{
			Tokens: &vault.Tokens{
				EDV: "edv-token",
				KMS: "kms-token",
			},
		},
		nil,
	)

	srv := collect.NewService(comparator, vaultClient)

	auth, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.NoError(t, err)
	require.Equal(t, "auth-token", auth)
}

func TestCollect_BadConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	vaultClient := NewMockVault(ctrl)

	comparator.EXPECT().GetConfig(gomock.Any()).Return(nil, errors.New("bad config"))

	srv := collect.NewService(comparator, vaultClient)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "bad config")
}

func TestCollect_BadAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	vaultClient := NewMockVault(ctrl)

	comparator.EXPECT().GetConfig(gomock.Any()).Return(&operations.GetConfigOK{
		Payload: &compmodel.Config{
			AuthKeyURL: "did:orb:comparator123456",
		},
	}, nil)

	vaultClient.EXPECT().CreateAuthorization(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, errors.New("create authorization failed"))

	srv := collect.NewService(comparator, vaultClient)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "create authorization failed")
}

func TestCollect_PostAuthorizationFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	vaultClient := NewMockVault(ctrl)

	comparator.EXPECT().GetConfig(gomock.Any()).Return(&operations.GetConfigOK{
		Payload: &compmodel.Config{
			AuthKeyURL: "did:orb:comparator123456",
		},
	}, nil)

	comparator.EXPECT().PostAuthorizations(gomock.Any()).
		Return(nil, errors.New("post authorization failed"))

	vaultClient.EXPECT().CreateAuthorization(
		"did:orb:vault12345", "did:orb:comparator123456", gomock.Any()).Return(
		&vault.CreatedAuthorization{
			Tokens: &vault.Tokens{
				EDV: "edv-token",
				KMS: "kms-token",
			},
		},
		nil,
	)

	srv := collect.NewService(comparator, vaultClient)

	_, err := srv.Collect(context.Background(), &protect.ProtectedData{
		DID: "did:orb:vault12345",
	}, "did:orb:rp123456")

	require.Contains(t, err.Error(), "post authorization failed")
}

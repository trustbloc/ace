/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	"github.com/trustbloc/ace/pkg/client/csh/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/config"
)

func TestService_CreateConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").Return(nil, nil)

		zcap := &zcapld.Capability{
			Proof: []verifiable.Proof{
				map[string]interface{}{
					"verificationMethod": "did:orb:test12345#key1234",
				},
			},
		}

		compZCAP, err := zcapld.CompressZCAP(zcap)
		require.NoError(t, err)

		csh.EXPECT().PostHubstoreProfiles(gomock.Any()).Return(
			&operations.PostHubstoreProfilesCreated{
				Payload: &models.Profile{
					Zcap: compZCAP,
				},
			}, nil)

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.NoError(t, err)
	})

	t.Run("Invalid verification", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").Return(nil, nil)

		zcap := &zcapld.Capability{
			Proof: []verifiable.Proof{
				map[string]interface{}{
					"verificationMethod": 10,
				},
			},
		}

		compZCAP, err := zcapld.CompressZCAP(zcap)
		require.NoError(t, err)

		csh.EXPECT().PostHubstoreProfiles(gomock.Any()).Return(
			&operations.PostHubstoreProfilesCreated{
				Payload: &models.Profile{
					Zcap: compZCAP,
				},
			}, nil)

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.Error(t, err)
	})

	t.Run("ZCAP decompress failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").Return(nil, nil)

		csh.EXPECT().PostHubstoreProfiles(gomock.Any()).Return(
			&operations.PostHubstoreProfilesCreated{
				Payload: &models.Profile{
					Zcap: "",
				},
			}, nil)

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.Error(t, err)
	})

	t.Run("Create CSH profile failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").Return(nil, nil)

		csh.EXPECT().PostHubstoreProfiles(gomock.Any()).Return(nil,
			errors.New("create profile failed"))

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.EqualError(t, err, "create profile failed")
	})

	t.Run("Create CSH profile failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").Return(nil, nil)

		csh.EXPECT().PostHubstoreProfiles(gomock.Any()).Return(nil,
			errors.New("create profile failed"))

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.EqualError(t, err, "create profile failed")
	})

	t.Run("Resolve did failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			&docdid.DocResolution{
				DIDDocument: &docdid.Doc{
					ID: "did:orb:test123456",
				},
			}, nil)

		vdr.EXPECT().Resolve("did:orb:test123456").
			Return(nil, errors.New("DID does not exist")).Times(10)

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.Contains(t, err.Error(), "failed to resolve DID")
	})

	t.Run("Create did failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		vdr.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			nil, errors.New("create did failed"))

		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.Contains(t, err.Error(), "create did failed")
	})

	t.Run("Create key failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)

		vdr := NewMockVDRRegistry(ctrl)

		kmsService := &kms.KeyManager{}
		kmsService.CrAndExportPubKeyErr = errors.New("create key failed")

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		err = cfgService.CreateConfig()

		require.Contains(t, err.Error(), "create key failed")
	})
}

func TestService_HasConfig(t *testing.T) {
	t.Run("Success(false)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		csh := NewMockCSHClient(ctrl)
		vdr := NewMockVDRRegistry(ctrl)
		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		has, err := cfgService.HasConfig()

		require.False(t, has)
		require.NoError(t, err)
	})

	t.Run("Success(true)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		storeProvider.Store.Store["config"] = storage.DBEntry{Value: []byte("test")}

		csh := NewMockCSHClient(ctrl)
		vdr := NewMockVDRRegistry(ctrl)
		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		has, err := cfgService.HasConfig()

		require.True(t, has)
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		storeProvider.Store.ErrGet = errors.New("db error")

		csh := NewMockCSHClient(ctrl)
		vdr := NewMockVDRRegistry(ctrl)
		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		_, err = cfgService.HasConfig()

		require.Contains(t, err.Error(), "db error")
	})
}

func TestService_Get(t *testing.T) {
	t.Run("Success(false)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()
		storeProvider.Store.Store["config"] = storage.DBEntry{Value: []byte("{}")}

		csh := NewMockCSHClient(ctrl)
		vdr := NewMockVDRRegistry(ctrl)
		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		cfg, err := cfgService.Get()

		require.NotNil(t, cfg)
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storeProvider := storage.NewMockStoreProvider()

		storeProvider.Store.ErrGet = errors.New("db error")

		csh := NewMockCSHClient(ctrl)
		vdr := NewMockVDRRegistry(ctrl)
		kmsService := &kms.KeyManager{}

		cfgService, err := config.NewService(&config.ServiceParams{
			StoreProvider:   storeProvider,
			CSHClient:       csh,
			VDR:             vdr,
			KeyManager:      kmsService,
			DidMethod:       "test",
			DidAnchorOrigin: "test",
		})

		require.NoError(t, err)
		require.NotNil(t, cfgService)

		_, err = cfgService.Get()

		require.Contains(t, err.Error(), "db error")
	})
}

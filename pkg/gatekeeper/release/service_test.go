/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package release_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release"
)

const (
	testDID      = "did:example:test"
	testApprover = "did:example:approver"
	testPolicyID = "test-policy"
	testTicketID = "test-ticket"
	testTicket   = `{
	  "id": "test-ticket",
	  "did": "did:example:test",
	  "status": 0,
	  "approved_by": [
		"did:example:approver"
	  ]
	}`
	testTicketWithoutApprovements = `{
	  "id": "test-ticket",
	  "did": "did:example:test",
	  "status": 0,
	  "approved_by": []
	}`
)

func TestNewService(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.ErrOpenStoreHandle = errors.New("open error")

		svc, err := release.NewService(&release.Config{
			StoreProvider: store,
		})

		require.EqualError(t, err, "open ticket store: open error")
		require.Nil(t, svc)
	})

	t.Run("Success", func(t *testing.T) {
		svc, err := release.NewService(&release.Config{
			StoreProvider: storage.NewMockStoreProvider(),
		})

		require.NoError(t, err)
		require.NotNil(t, svc)
	})
}

func TestService_Release(t *testing.T) {
	t.Run("Fail to store ticket", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("put error")

		svc, err := release.NewService(&release.Config{
			StoreProvider: store,
		})
		require.NoError(t, err)

		ticket, err := svc.Release(context.Background(), testDID)

		require.EqualError(t, err, "store ticket: put error")
		require.Nil(t, ticket)
	})

	t.Run("Success", func(t *testing.T) {
		svc, err := release.NewService(&release.Config{
			StoreProvider: storage.NewMockStoreProvider(),
		})
		require.NoError(t, err)

		ticket, err := svc.Release(context.Background(), testDID)

		require.NoError(t, err)
		require.NotNil(t, ticket)
	})
}

func TestService_Get(t *testing.T) {
	t.Run("Fail to get ticket", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrGet = errors.New("get error")

		svc, err := release.NewService(&release.Config{
			StoreProvider: store,
		})
		require.NoError(t, err)

		ticket, err := svc.Get(context.Background(), testTicketID)

		require.EqualError(t, err, "get ticket: get error")
		require.Nil(t, ticket)
	})

	t.Run("Success", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicket)}

		svc, err := release.NewService(&release.Config{
			StoreProvider: store,
		})
		require.NoError(t, err)

		ticket, err := svc.Get(context.Background(), testTicketID)

		require.NoError(t, err)
		require.NotNil(t, ticket)
	})
}

func TestService_Authorize(t *testing.T) {
	t.Run("Fail to get ticket to authorize", func(t *testing.T) {
		store := storage.NewMockStoreProvider()
		store.Store.ErrGet = errors.New("get error")

		svc, err := release.NewService(&release.Config{
			StoreProvider: store,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.EqualError(t, err, "get ticket to authorize: get ticket: get error")
	})

	t.Run("Fail to get protected data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicket)}

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), testDID).Return(nil, errors.New("get error"))

		svc, err := release.NewService(&release.Config{
			StoreProvider:  store,
			ProtectService: protectService,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.EqualError(t, err, "get protected data: get error")
	})

	t.Run("Fail to get policy", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicket)}

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), testDID).Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Get(gomock.Any(), testPolicyID).Return(nil, errors.New("get error"))

		svc, err := release.NewService(&release.Config{
			StoreProvider:  store,
			ProtectService: protectService,
			PolicyService:  policyService,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.EqualError(t, err, "get policy: get error")
	})

	t.Run("Fail to store ticket", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicket)}
		store.Store.ErrPut = errors.New("put error")

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), testDID).Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Get(gomock.Any(), testPolicyID).Return(&policy.Policy{
			ID:           testPolicyID,
			Approvers:    []string{testApprover},
			MinApprovers: 1,
		}, nil)

		svc, err := release.NewService(&release.Config{
			StoreProvider:  store,
			ProtectService: protectService,
			PolicyService:  policyService,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.EqualError(t, err, "update ticket: put error")
	})

	t.Run("Success: ticket in READY_TO_COLLECT state", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicket)}

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), testDID).Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Get(gomock.Any(), testPolicyID).Return(&policy.Policy{
			ID:           testPolicyID,
			Approvers:    []string{testApprover},
			MinApprovers: 1,
		}, nil)

		svc, err := release.NewService(&release.Config{
			StoreProvider:  store,
			ProtectService: protectService,
			PolicyService:  policyService,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.NoError(t, err)
	})

	t.Run("Success: ticket in COLLECTING state", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := storage.NewMockStoreProvider()
		store.Store.Store[testTicketID] = storage.DBEntry{Value: []byte(testTicketWithoutApprovements)}

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), testDID).Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Get(gomock.Any(), testPolicyID).Return(&policy.Policy{
			ID:           testPolicyID,
			Approvers:    []string{testApprover, "did:example:another-approver"},
			MinApprovers: 2,
		}, nil)

		svc, err := release.NewService(&release.Config{
			StoreProvider:  store,
			ProtectService: protectService,
			PolicyService:  policyService,
		})
		require.NoError(t, err)

		err = svc.Authorize(context.Background(), testTicketID, testApprover)

		require.NoError(t, err)
	})
}

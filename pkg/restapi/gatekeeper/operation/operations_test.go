/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
)

const (
	subjectDID   = "did:example:subject"
	targetDID    = "did:example:target"
	testPolicyID = "test-policy"
	testTicketID = "test-ticket"
)

func TestProtectHandler(t *testing.T) {
	req := &operation.ProtectRequest{
		Policy: "10",
		Target: "test ssn",
	}

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).Return(&protect.ProtectedData{}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), req.Policy, subjectDID, policy.Collector).Return(nil)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ProtectService:  protectService,
			PolicyService:   policyService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		op := &operation.Operation{}

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost,
			bytes.NewBufferString("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to resolve subject DID from context", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return("", errors.New("resolve error"))

		op := &operation.Operation{
			ProtectService:  protectService,
			PolicyService:   policyService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Fail to check policy: ErrNotAllowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), req.Policy, subjectDID, policy.Collector).
			Return(policy.ErrNotAllowed)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ProtectService:  protectService,
			PolicyService:   policyService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Fail to check policy: internal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), req.Policy, subjectDID, policy.Collector).
			Return(errors.New("policy check error"))

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ProtectService:  protectService,
			PolicyService:   policyService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Fail to protect data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("protect failed"))

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), req.Policy, subjectDID, policy.Collector).Return(nil)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ProtectService:  protectService,
			PolicyService:   policyService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestCreatePolicyHandler(t *testing.T) {
	p := &policy.Policy{
		Collectors:   []string{"did:example:ray_stantz"},
		Handlers:     []string{"did:example:alter_peck"},
		Approvers:    []string{"did:example:peter_venkman", "did:example:eon_spengler", "did:example:winton_zeddemore"},
		MinApprovers: 2,
	}

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil).Times(1)

		op := &operation.Operation{
			PolicyService: policyService,
		}

		body, err := json.Marshal(p)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Save(gomock.Any(), gomock.Any()).Times(0)

		op := &operation.Operation{
			PolicyService: policyService,
		}

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut,
			bytes.NewBufferString("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to store policy", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errors.New("save error")).Times(1)

		op := &operation.Operation{
			PolicyService: policyService,
		}

		body, err := json.Marshal(p)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestReleaseHandler(t *testing.T) {
	req := operation.ReleaseRequest{
		DID: targetDID,
	}

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Release(gomock.Any(), targetDID).Return(&ticket.Ticket{}, nil).Times(1)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).
			Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil).Times(1)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Handler).Return(nil).Times(1)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		svc := NewMockReleaseService(ctrl)
		svc.EXPECT().Release(gomock.Any(), targetDID).Times(0)

		op := &operation.Operation{
			ReleaseService: svc,
		}

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewBufferString("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to get protected data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Release(gomock.Any(), gomock.Any()).Times(0)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(nil, errors.New("get error")).Times(1)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Times(0)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Fail to check policy: ErrNotAllowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Release(gomock.Any(), gomock.Any()).Times(0)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).
			Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil).Times(1)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Handler).
			Return(policy.ErrNotAllowed).Times(1)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Fail to create release transaction on a DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Release(gomock.Any(), targetDID).Return(nil, errors.New("release error"))

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).
			Return(&protect.ProtectedData{PolicyID: testPolicyID}, nil).Times(1)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Handler).Return(nil).Times(1)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestAuthorizeHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)
		releaseService.EXPECT().Authorize(gomock.Any(), testTicketID, subjectDID).Return(nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(&protect.ProtectedData{
			PolicyID: testPolicyID,
		}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Approver).Return(nil)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Ticket not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(nil, storage.ErrDataNotFound)

		op := &operation.Operation{
			ReleaseService: releaseService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to get ticket", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(nil, errors.New("get error"))

		op := &operation.Operation{
			ReleaseService: releaseService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Fail to get protected data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(nil, errors.New("get error"))

		op := &operation.Operation{
			ReleaseService: releaseService,
			ProtectService: protectService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Not allowed per policy", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(&protect.ProtectedData{
			PolicyID: testPolicyID,
		}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Approver).Return(policy.ErrNotAllowed)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Fail to authorize ticket", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)
		releaseService.EXPECT().Authorize(gomock.Any(), testTicketID, subjectDID).Return(errors.New("authorize error"))

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(&protect.ProtectedData{
			PolicyID: testPolicyID,
		}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Approver).Return(nil)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/authorize", http.MethodPost, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestTicketStatusHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(&protect.ProtectedData{
			PolicyID: testPolicyID,
		}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Handler).Return(nil)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/status", http.MethodGet, nil)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Ticket not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(nil, storage.ErrDataNotFound)

		op := &operation.Operation{
			ReleaseService: releaseService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/status", http.MethodGet, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to get ticket", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(nil, errors.New("get error"))

		op := &operation.Operation{
			ReleaseService: releaseService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/status", http.MethodGet, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Fail to get protected data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(nil, errors.New("get error"))

		op := &operation.Operation{
			ReleaseService: releaseService,
			ProtectService: protectService,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/status", http.MethodGet, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Not allowed per policy", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		releaseService := NewMockReleaseService(ctrl)
		releaseService.EXPECT().Get(gomock.Any(), testTicketID).Return(&ticket.Ticket{
			ID:     testTicketID,
			DID:    targetDID,
			Status: 0,
		}, nil)

		protectService := NewMockProtectService(ctrl)
		protectService.EXPECT().Get(gomock.Any(), targetDID).Return(&protect.ProtectedData{
			PolicyID: testPolicyID,
		}, nil)

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Check(gomock.Any(), testPolicyID, subjectDID, policy.Handler).Return(policy.ErrNotAllowed)

		subjectResolver := NewMockSubjectResolver(ctrl)
		subjectResolver.EXPECT().Resolve(gomock.Any()).Return(subjectDID, nil)

		op := &operation.Operation{
			ReleaseService:  releaseService,
			PolicyService:   policyService,
			ProtectService:  protectService,
			SubjectResolver: subjectResolver,
		}

		rr := handleRequest(t, op, "/v1/release/test-ticket/status", http.MethodGet, nil)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func handleRequest(t *testing.T, op *operation.Operation, path, method string, body io.Reader,
) *httptest.ResponseRecorder {
	t.Helper()

	router := mux.NewRouter()

	for _, h := range op.GetRESTHandlers() {
		router.HandleFunc(h.Path(), h.Handle()).Methods(h.Method())
	}

	req, err := http.NewRequestWithContext(context.Background(), method, path, body)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr
}

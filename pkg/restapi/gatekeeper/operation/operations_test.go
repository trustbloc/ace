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
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
	"github.com/trustbloc/ace/pkg/restapi/model"
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

		op := &operation.Operation{
			ProtectService: protectService,
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

	t.Run("Fail to protect data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		protectSvc := NewMockProtectService(ctrl)
		protectSvc.EXPECT().Protect(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("protect failed"))

		op := &operation.Operation{
			ProtectService: protectSvc,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/protect", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestCreatePolicyHandler(t *testing.T) {
	policy := &model.PolicyDocument{
		Collectors:   []string{"did:example:ray_stantz"},
		Handlers:     []string{"did:example:alter_peck"},
		Approvers:    []string{"did:example:peter_venkman", "did:example:eon_spengler", "did:example:winton_zeddemore"},
		MinApprovers: 2,
	}

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Save(gomock.Any()).Return(nil).Times(1)

		op := &operation.Operation{
			PolicyService: policyService,
		}

		body, err := json.Marshal(policy)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		policyService := NewMockPolicyService(ctrl)
		policyService.EXPECT().Save(gomock.Any()).Times(0)

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
		policyService.EXPECT().Save(gomock.Any()).Return(errors.New("save error")).Times(1)

		op := &operation.Operation{
			PolicyService: policyService,
		}

		body, err := json.Marshal(policy)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestReleaseHandler(t *testing.T) {
	const testDID = "did:example:test"

	req := operation.ReleaseRequest{
		DID: testDID,
	}

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		svc := NewMockReleaseService(ctrl)
		svc.EXPECT().Release(gomock.Any(), testDID).Return(&ticket.Ticket{}, nil)

		op := &operation.Operation{
			ReleaseService: svc,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		svc := NewMockReleaseService(ctrl)
		svc.EXPECT().Release(gomock.Any(), testDID).Times(0)

		op := &operation.Operation{
			ReleaseService: svc,
		}

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewBufferString("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to create release transaction on a DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		svc := NewMockReleaseService(ctrl)
		svc.EXPECT().Release(gomock.Any(), testDID).Return(nil, errors.New("release error"))

		op := &operation.Operation{
			ReleaseService: svc,
		}

		body, err := json.Marshal(req)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/release", http.MethodPost, bytes.NewReader(body))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
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

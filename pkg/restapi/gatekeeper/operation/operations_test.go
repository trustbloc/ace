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

	"github.com/gorilla/mux"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
	"github.com/trustbloc/ace/pkg/restapi/model"
)

func TestCreatePolicyHandler(t *testing.T) {
	policy := &model.PolicyDocument{
		Collectors:   []string{"did:example:ray_stantz"},
		Handlers:     []string{"did:example:alter_peck"},
		Approvers:    []string{"did:example:peter_venkman", "did:example:eon_spengler", "did:example:winton_zeddemore"},
		MinApprovers: 2,
	}

	t.Run("Success", func(t *testing.T) {
		op, err := operation.New(&operation.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			VaultClient:     nil,
			VDRI:            nil,
			VCProvider:      nil,
		})
		require.NoError(t, err)

		body, err := json.Marshal(policy)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to unmarshal request body", func(t *testing.T) {
		op, err := operation.New(&operation.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			VaultClient:     nil,
			VDRI:            nil,
			VCProvider:      nil,
		})
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut,
			bytes.NewBufferString("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail to store policy", func(t *testing.T) {
		p := mockstorage.NewMockStoreProvider()
		p.Store.ErrPut = errors.New("put error")

		op, err := operation.New(&operation.Config{
			StorageProvider: p,
			VaultClient:     nil,
			VDRI:            nil,
			VCProvider:      nil,
		})
		require.NoError(t, err)

		body, err := json.Marshal(policy)
		require.NoError(t, err)

		rr := handleRequest(t, op, "/v1/policy/containment-policy", http.MethodPut, bytes.NewReader(body))

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

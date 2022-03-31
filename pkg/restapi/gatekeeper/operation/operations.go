/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package operation_test -source=operations.go -mock_names protectOperation=MockProtectOperation,policyStore=MockPolicyStore

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/ace/pkg/internal/common/support"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/model"
)

type protectOperation interface {
	ProtectOp(req *models.ProtectReq) (*models.ProtectResp, error)
}

type policyStore interface {
	Put(policyID string, doc *model.PolicyDocument) error
}

var logger = log.New("gatekeeper")

// API endpoints.
const (
	policyIDVarName = "policy_id"
	baseV1Path      = "/v1"
	protectEndpoint = baseV1Path + "/protect"
	policyEndpoint  = baseV1Path + "/policy/{" + policyIDVarName + "}"
)

// Operation defines handlers for rp operations.
type Operation struct {
	ProtectOperation protectOperation
	PolicyStore      policyStore
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler),
		support.NewHTTPHandler(policyEndpoint, http.MethodPut, o.createPolicyHandler),
	}
}

func (o *Operation) protectHandler(rw http.ResponseWriter, r *http.Request) {
	req := &models.ProtectReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	response, err := o.ProtectOperation.ProtectOp(req)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	respond(rw, http.StatusOK, response)
}

func (o *Operation) createPolicyHandler(rw http.ResponseWriter, r *http.Request) {
	doc := model.PolicyDocument{}

	err := json.NewDecoder(r.Body).Decode(&doc)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	policyID := strings.ToLower(mux.Vars(r)[policyIDVarName])

	err = o.PolicyStore.Put(policyID, &doc)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, fmt.Errorf("store policy: %w", err))

		return
	}

	respond(rw, http.StatusOK, nil)
}

func respond(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json")

	w.WriteHeader(statusCode)

	if payload != nil {
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			logger.Errorf("failed to write response: %s", err.Error())
		}
	}
}

func respondError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Add("Content-Type", "application/json")

	errorMessage := err.Error()

	logger.Errorf(errorMessage)

	w.WriteHeader(statusCode)

	if encErr := json.NewEncoder(w).Encode(&model.ErrorResponse{Message: errorMessage}); encErr != nil {
		logger.Errorf("failed to write error response: %s", err.Error())
	}
}

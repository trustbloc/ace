/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package operation_test -source=operations.go -mock_names policyService=MockPolicyService,protectService=MockProtectService,releaseService=MockReleaseService

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
	"github.com/trustbloc/ace/pkg/internal/common/support"
	"github.com/trustbloc/ace/pkg/restapi/model"
)

const (
	policyIDVarName = "policy_id"
	baseV1Path      = "/v1"
	protectEndpoint = baseV1Path + "/protect"
	policyEndpoint  = baseV1Path + "/policy/{" + policyIDVarName + "}"
	releaseEndpoint = baseV1Path + "/release"
)

var logger = log.New("gatekeeper")

type policyService interface {
	Save(doc *policy.Policy) error
}

type protectService interface {
	Protect(ctx context.Context, data, policyID string) (*protect.ProtectedData, error)
}

type releaseService interface {
	Release(ctx context.Context, did string) (*ticket.Ticket, error)
}

// Operation defines handlers for Gatekeeper operations.
type Operation struct {
	PolicyService  policyService
	ProtectService protectService
	ReleaseService releaseService
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(policyEndpoint, http.MethodPut, o.createPolicyHandler),
		support.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler),
		support.NewHTTPHandler(releaseEndpoint, http.MethodPost, o.releaseHandler),
	}
}

func (o *Operation) createPolicyHandler(rw http.ResponseWriter, r *http.Request) {
	var p policy.Policy

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	p.ID = strings.ToLower(mux.Vars(r)[policyIDVarName])

	err = o.PolicyService.Save(&p)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, fmt.Errorf("save policy: %w", err))

		return
	}

	respond(rw, http.StatusOK, nil)
}

func (o *Operation) protectHandler(rw http.ResponseWriter, r *http.Request) {
	var req ProtectRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	protectedData, err := o.ProtectService.Protect(r.Context(), req.Target, req.Policy)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	respond(rw, http.StatusOK, &ProtectResponse{DID: protectedData.DID})
}

func (o *Operation) releaseHandler(rw http.ResponseWriter, r *http.Request) {
	var req ReleaseRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	// TODO: resolve and save into context handler DID

	t, err := o.ReleaseService.Release(r.Context(), req.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	respond(rw, http.StatusOK, &ReleaseResponse{TicketID: t.ID})
}

func respond(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json")

	w.WriteHeader(statusCode)

	if payload != nil {
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			logger.Errorf("Failed to write response: %s", err.Error())
		}
	}
}

func respondError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Add("Content-Type", "application/json")

	errorMessage := err.Error()

	logger.Errorf(errorMessage)

	w.WriteHeader(statusCode)

	if encErr := json.NewEncoder(w).Encode(&model.ErrorResponse{Message: errorMessage}); encErr != nil {
		logger.Errorf("Failed to write error response: %s", err.Error())
	}
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package operation_test -source=operations.go -mock_names policyService=MockPolicyService,protectService=MockProtectService,releaseService=MockReleaseService,subjectResolver=MockSubjectResolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
	"github.com/trustbloc/ace/pkg/restapi/handler"
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
	Save(ctx context.Context, doc *policy.Policy) error
	Check(ctx context.Context, policyID, did string, role policy.Role) error
}

type protectService interface {
	Protect(ctx context.Context, data, policyID string) (*protect.ProtectedData, error)
	Get(ctx context.Context, did string) (*protect.ProtectedData, error)
}

type releaseService interface {
	Release(ctx context.Context, did string) (*ticket.Ticket, error)
}

type subjectResolver interface {
	Resolve(ctx context.Context) (string, error)
}

// Operation defines handlers for Gatekeeper operations.
type Operation struct {
	PolicyService   policyService
	ProtectService  protectService
	ReleaseService  releaseService
	SubjectResolver subjectResolver
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []handler.Handler {
	return []handler.Handler{
		handler.NewHTTPHandler(policyEndpoint, http.MethodPut, o.createPolicyHandler, handler.WithAuth(handler.AuthToken)),
		handler.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler, handler.WithAuth(handler.AuthHTTPSig)),
		handler.NewHTTPHandler(releaseEndpoint, http.MethodPost, o.releaseHandler, handler.WithAuth(handler.AuthHTTPSig)),
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

	err = o.PolicyService.Save(r.Context(), &p)
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

	if err = o.checkPolicy(r.Context(), req.Policy, policy.Collector); err != nil {
		respondError(rw, err.(*policyError).status, err) //nolint:errorlint,forcetypeassert

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

	protectedData, err := o.ProtectService.Get(r.Context(), req.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	if err = o.checkPolicy(r.Context(), protectedData.PolicyID, policy.Handler); err != nil {
		respondError(rw, err.(*policyError).status, err) //nolint:errorlint,forcetypeassert

		return
	}

	t, err := o.ReleaseService.Release(r.Context(), req.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	respond(rw, http.StatusOK, &ReleaseResponse{TicketID: t.ID})
}

type policyError struct {
	status int
	err    error
}

func (e *policyError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}

	return ""
}

func (o *Operation) checkPolicy(ctx context.Context, policyID string, role policy.Role) error {
	sub, err := o.SubjectResolver.Resolve(ctx)
	if err != nil {
		return &policyError{status: http.StatusUnauthorized, err: err}
	}

	err = o.PolicyService.Check(ctx, policyID, sub, role)
	if err != nil {
		if errors.Is(err, policy.ErrNotAllowed) {
			return &policyError{status: http.StatusUnauthorized, err: err}
		}

		return &policyError{status: http.StatusInternalServerError, err: err}
	}

	return nil
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

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package operation_test -source=operations.go -mock_names policyService=MockPolicyService,protectService=MockProtectService,releaseService=MockReleaseService,subjectResolver=MockSubjectResolver,collectService=MockCollectService,extractService=MockExtractService

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release/ticket"
	"github.com/trustbloc/ace/pkg/restapi/handler"
	"github.com/trustbloc/ace/pkg/restapi/model"
)

const (
	policyIDVarName      = "policy_id"
	ticketIDVarName      = "ticket_id"
	baseV1Path           = "/v1"
	protectEndpoint      = baseV1Path + "/protect"
	policyEndpoint       = baseV1Path + "/policy/{" + policyIDVarName + "}"
	releaseEndpoint      = baseV1Path + "/release"
	authorizeEndpoint    = releaseEndpoint + "/{" + ticketIDVarName + "}/authorize"
	ticketStatusEndpoint = releaseEndpoint + "/{" + ticketIDVarName + "}/status"
	collectEndpoint      = releaseEndpoint + "/{" + ticketIDVarName + "}/collect"
	extractEndpoint      = baseV1Path + "/extract"
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
	Get(ctx context.Context, ticketID string) (*ticket.Ticket, error)
	Authorize(ctx context.Context, ticketID, approverDID string) error
}

type collectService interface {
	Collect(ctx context.Context, protectedData *protect.ProtectedData, requestingPartyDID string) (string, error)
}

type extractService interface {
	Extract(ctx context.Context, authToken string) (string, error)
}

type subjectResolver interface {
	Resolve(ctx context.Context) (string, error)
}

// Operation defines handlers for Gatekeeper operations.
type Operation struct {
	SubjectResolver subjectResolver
	PolicyService   policyService
	ProtectService  protectService
	ReleaseService  releaseService
	CollectService  collectService
	ExtractService  extractService
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []handler.Handler {
	return []handler.Handler{
		handler.NewHTTPHandler(policyEndpoint, http.MethodPut, o.createPolicyHandler, handler.WithAuth(handler.AuthToken)),
		handler.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler, handler.WithAuth(handler.AuthHTTPSig)),
		handler.NewHTTPHandler(releaseEndpoint, http.MethodPost, o.releaseHandler, handler.WithAuth(handler.AuthHTTPSig)),
		handler.NewHTTPHandler(authorizeEndpoint, http.MethodPost, o.authorizeHandler, handler.WithAuth(handler.AuthHTTPSig)),
		handler.NewHTTPHandler(ticketStatusEndpoint, http.MethodGet, o.ticketStatusHandler, handler.WithAuth(handler.AuthHTTPSig)), //nolint:lll
		handler.NewHTTPHandler(collectEndpoint, http.MethodPost, o.collectHandler, handler.WithAuth(handler.AuthHTTPSig)),
		handler.NewHTTPHandler(extractEndpoint, http.MethodPost, o.extractHandler),
	}
}

// createPolicyHandler swagger:route PUT /v1/policy/{policy_id} gatekeeper createPolicyReq
//
// Creates policy configuration for storing and releasing protected data.
//
// Responses:
//     200: createPolicyResp
//     default: errorResp
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

// protectHandler swagger:route POST /v1/protect gatekeeper protectReq
//
// Converts a social media handle (or other sensitive string data) into a DID.
//
// Responses:
//     200: protectResp
//     default: errorResp
func (o *Operation) protectHandler(rw http.ResponseWriter, r *http.Request) {
	var req ProtectRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	if _, err = o.checkPolicy(r.Context(), req.Policy, policy.Collector); err != nil {
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

// releaseHandler swagger:route POST /v1/release gatekeeper releaseReq
//
// Creates a new release transaction (ticket) on a DID.
//
// Responses:
//     200: releaseResp
//     default: errorResp
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

	if _, err = o.checkPolicy(r.Context(), protectedData.PolicyID, policy.Handler); err != nil {
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

// authorizeHandler swagger:route POST /v1/release/{ticket_id}/authorize gatekeeper authorizeReq
//
// Authorizes release transaction (ticket).
//
// Responses:
//     200: authorizeResp
//     default: errorResp
func (o *Operation) authorizeHandler(rw http.ResponseWriter, r *http.Request) {
	ticketID := mux.Vars(r)[ticketIDVarName]

	t, err := o.ReleaseService.Get(r.Context(), ticketID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			respondError(rw, http.StatusBadRequest, err)
		}

		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	protectedData, err := o.ProtectService.Get(r.Context(), t.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	var sub string

	if sub, err = o.checkPolicy(r.Context(), protectedData.PolicyID, policy.Approver); err != nil {
		respondError(rw, err.(*policyError).status, err) //nolint:errorlint,forcetypeassert

		return
	}

	if err = o.ReleaseService.Authorize(r.Context(), ticketID, sub); err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	respond(rw, http.StatusOK, nil)
}

// ticketStatusHandler swagger:route GET /v1/release/{ticket_id}/status gatekeeper ticketStatusReq
//
// Gets the status of the ticket.
//
// Responses:
//     200: ticketStatusResp
//     default: errorResp
func (o *Operation) ticketStatusHandler(rw http.ResponseWriter, r *http.Request) {
	ticketID := mux.Vars(r)[ticketIDVarName]

	t, err := o.ReleaseService.Get(r.Context(), ticketID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			respondError(rw, http.StatusBadRequest, err)
		}

		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	protectedData, err := o.ProtectService.Get(r.Context(), t.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	if _, err = o.checkPolicy(r.Context(), protectedData.PolicyID, policy.Handler); err != nil {
		respondError(rw, err.(*policyError).status, err) //nolint:errorlint,forcetypeassert

		return
	}

	respond(rw, http.StatusOK, &TicketStatusResponse{Status: t.Status.String()})
}

// collectHandler swagger:route POST /v1/release/{ticket_id}/collect gatekeeper collectReq
//
// Generates extract query for the ticket that has completed authorization process.
//
// Responses:
//     200: collectResp
//     default: errorResp
func (o *Operation) collectHandler(rw http.ResponseWriter, r *http.Request) {
	ticketID := strings.ToLower(mux.Vars(r)[ticketIDVarName])

	t, err := o.ReleaseService.Get(r.Context(), ticketID)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	protectedData, err := o.ProtectService.Get(r.Context(), t.DID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, err)

		return
	}

	if t.Status != ticket.ReadyToCollect {
		respondError(rw, http.StatusUnauthorized, errors.New("not authorized to access ticket"))

		return
	}

	subDID, err := o.checkPolicy(r.Context(), protectedData.PolicyID, policy.Handler)
	if err != nil {
		respondError(rw, err.(*policyError).status, err) //nolint:errorlint,forcetypeassert

		return
	}

	queryID, err := o.CollectService.Collect(r.Context(), protectedData, subDID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, errors.New("fail to collect data"))

		return
	}

	respond(rw, http.StatusOK, &CollectResponse{QueryID: queryID})
}

// extractHandler swagger:route POST /v1/extract gatekeeper extractReq
//
// Extracts protected data.
//
// Responses:
//     200: extractResp
//     default: errorResp
func (o *Operation) extractHandler(rw http.ResponseWriter, r *http.Request) {
	var req ExtractRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondError(rw, http.StatusBadRequest, err)

		return
	}

	target, err := o.ExtractService.Extract(r.Context(), req.QueryID)
	if err != nil {
		respondError(rw, http.StatusInternalServerError, errors.New("fail to resolve subject"))

		return
	}

	respond(rw, http.StatusOK, &ExtractResponse{Target: target})
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

func (o *Operation) checkPolicy(ctx context.Context, policyID string, role policy.Role) (string, error) {
	sub, err := o.SubjectResolver.Resolve(ctx)
	if err != nil {
		return "", &policyError{status: http.StatusUnauthorized, err: err}
	}

	err = o.PolicyService.Check(ctx, policyID, sub, role)
	if err != nil {
		if errors.Is(err, policy.ErrNotAllowed) {
			return "", &policyError{status: http.StatusUnauthorized, err: err}
		}

		return "", &policyError{status: http.StatusInternalServerError, err: err}
	}

	return sub, nil
}

func respond(w http.ResponseWriter, statusCode int, payload interface{}) { //nolint:unparam
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

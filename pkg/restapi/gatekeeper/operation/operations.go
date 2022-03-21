/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/internal/common/support"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/vcprovider"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/repository"
	"github.com/trustbloc/ace/pkg/restapi/model"
)

var logger = log.New("gatekeeper")

// API endpoints.
const (
	protectEndpoint = "/gatekeeper"
)

// Config defines configuration for gatekeeper operations.
type Config struct {
	StoreProvider storage.Provider
	VaultClient   vault.Vault
	VDRI          vdrapi.Registry
	VCProvider    vcprovider.Provider
}

// New returns CreateCredential instance.
func New(cfg *Config) (*Operation, error) {
	sensitiveDataRepository, err := repository.NewProtectedDataRepository(cfg.StoreProvider)
	if err != nil {
		return nil, err
	}

	protectOp := NewProtectOp(&ProtectConfig{
		SensitiveDataRepository: sensitiveDataRepository,
		VaultClient:             cfg.VaultClient,
		VDRI:                    cfg.VDRI,
		VCProvider:              cfg.VCProvider,
	})

	return &Operation{
		protectOperation: protectOp,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	protectOperation ProtectOperation
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler),
	}
}

func (o *Operation) protectHandler(rw http.ResponseWriter, r *http.Request) {
	req := &models.ProtectReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		logger.Errorf("gatekeeper response failure, %s", err)
	}

	response, err := o.protectOperation.ProtectOp(req)

	if err == nil {
		respond(rw, http.StatusOK, nil, response)
	} else {
		respondError(rw, http.StatusInternalServerError, err)
	}
}

func respond(w http.ResponseWriter, statusCode int, headers map[string]string, payload interface{}) {
	for k, v := range headers {
		w.Header().Add(k, v)
	}

	w.Header().Add("Content-Type", "application/json")

	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		logger.Errorf("failed to write response: %s", err.Error())
	}
}

func respondError(w http.ResponseWriter, statusCode int, err error) {
	msg := err.Error()

	w.Header().Add("Content-Type", "application/json")

	logger.Errorf(msg)
	w.WriteHeader(statusCode)

	err = json.NewEncoder(w).Encode(&model.ErrorResponse{
		Message: msg,
	})
	if err != nil {
		logger.Errorf("failed to write error response: %s", err.Error())
	}
}

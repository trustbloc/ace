/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/internal/common/support"
)

var logger = log.New("gatekeeper")

// API endpoints.
const (
	protectEndpoint = "/gatekeeper"
)

type protectReq struct {
	Target string `json:"target"`
	Policy string `json:"policy"`
}

type protectResp struct {
	DID string `json:"did"`
}

// Config defines configuration for gatekeeper operations.
type Config struct {
	StoreProvider storage.Provider
	HTTPClient    *http.Client
}

// New returns CreateCredential instance.
func New(cfg *Config) (*Operation, error) {
	return &Operation{
		httpClient: cfg.HTTPClient,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	httpClient *http.Client
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(protectEndpoint, http.MethodPost, o.protectHandler),
	}
}

func (o *Operation) protectHandler(rw http.ResponseWriter, r *http.Request) {
	req := protectReq{}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		logger.Errorf("gatekeeper response failure, %s", err)
	}

	rw.WriteHeader(http.StatusOK)

	err = json.NewEncoder(rw).Encode(&protectResp{
		DID: "did:example:12345",
	})
	if err != nil {
		logger.Errorf("gatekeeper response failure, %s", err)
	}
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcissuer

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package vcissuer_test -source=service.go -mock_names httpClient=MockHTTPClient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/ace/pkg/internal/httputil"
)

const (
	issueCredentialURLFormat = "%s/credentials/issue"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config represents configuration parameters for Service.
type Config struct {
	VCIssuerURL    string
	AuthToken      string
	DocumentLoader ld.DocumentLoader
	HTTPClient     httpClient
}

// Service is a service to issue verifiable credentials.
type Service struct {
	vcIssuerURL    string
	authToken      string
	documentLoader ld.DocumentLoader
	httpClient     httpClient
}

// New creates a new instance of issuer Service.
func New(config *Config) *Service {
	return &Service{
		vcIssuerURL:    config.VCIssuerURL,
		authToken:      config.AuthToken,
		documentLoader: config.DocumentLoader,
		httpClient:     config.HTTPClient,
	}
}

type issueCredentialReq struct {
	Credential json.RawMessage `json:"credential,omitempty"`
}

// IssueCredential issues verifiable credential.
func (s *Service) IssueCredential(ctx context.Context, cred []byte) (*verifiable.Credential, error) {
	req, err := json.Marshal(issueCredentialReq{
		Credential: cred,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal issue credential req: %w", err)
	}

	resp, err := httputil.DoRequest(ctx, fmt.Sprintf(issueCredentialURLFormat, s.vcIssuerURL),
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(req),
		httputil.WithHTTPClient(s.httpClient),
		httputil.WithAuthToken(s.authToken))
	if err != nil {
		return nil, fmt.Errorf("issue vc do request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("issue vc response status: %d", resp.StatusCode)
	}

	vc, err := verifiable.ParseCredential(resp.Body, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("parse vc: %w", err)
	}

	return vc, nil
}

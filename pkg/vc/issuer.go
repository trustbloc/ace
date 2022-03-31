/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package vc_test -source=issuer.go -mock_names httpClient=MockHTTPClient

import (
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

// Config for issuer service.
type Config struct {
	VCIssuerURL    string
	AuthToken      string
	DocumentLoader ld.DocumentLoader
	HTTPClient     httpClient
}

// Issuer service used to issue verifiable credential.
type Issuer struct {
	vcIssuerURL    string
	AuthToken      string
	documentLoader ld.DocumentLoader
	httpClient     httpClient
}

type issueCredentialRequest struct {
	Credential json.RawMessage `json:"credential,omitempty"`
}

// New creates vc provider.
func New(config *Config) *Issuer {
	return &Issuer{
		vcIssuerURL:    config.VCIssuerURL,
		AuthToken:      config.AuthToken,
		documentLoader: config.DocumentLoader,
		httpClient:     config.HTTPClient,
	}
}

// IssueCredential issue verifiable credential.
func (v *Issuer) IssueCredential(credBytes []byte) (*verifiable.Credential, error) {
	vcReq, err := json.Marshal(issueCredentialRequest{
		Credential: credBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vc request credential: %w", err)
	}

	endpoint := fmt.Sprintf(issueCredentialURLFormat, v.vcIssuerURL)

	vcResp, err := httputil.SendHTTPRequest(v.httpClient, http.MethodPost, endpoint, vcReq, http.StatusCreated,
		v.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create vc - url:%s err: %w", endpoint, err)
	}

	vc, err := verifiable.ParseCredential(vcResp, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(v.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("parse vc : %w", err)
	}

	return vc, nil
}

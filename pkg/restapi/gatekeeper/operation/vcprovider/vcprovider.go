/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcprovider

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/ace/pkg/internal/httputil"
)

const (
	issueCredentialURLFormat  = "%s" + "/credentials/issue"
	vcsIssuerRequestTokenName = "vcs_issuer"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider defines the interface to work with verifiable credential.
type Provider interface {
	IssueCredential(credBytes []byte) (*verifiable.Credential, error)
}

// Config for vc provider.
type Config struct {
	VCIssuerURL     string
	VCRequestTokens map[string]string
	DocumentLoader  ld.DocumentLoader
	HTTPClient      httpClient
}

type vcProvider struct {
	vcIssuerURL     string
	vcRequestTokens map[string]string
	documentLoader  ld.DocumentLoader
	httpClient      httpClient
}

type issueCredentialRequest struct {
	Credential json.RawMessage `json:"credential,omitempty"`
}

// New creates vc provider.
func New(config *Config) Provider { //nolint:ireturn
	return &vcProvider{
		vcIssuerURL:     config.VCIssuerURL,
		vcRequestTokens: config.VCRequestTokens,
		documentLoader:  config.DocumentLoader,
		httpClient:      config.HTTPClient,
	}
}

func (v *vcProvider) IssueCredential(credBytes []byte) (*verifiable.Credential, error) {
	vcReq, err := json.Marshal(issueCredentialRequest{
		Credential: credBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vc request credential: %w", err)
	}

	endpoint := fmt.Sprintf(issueCredentialURLFormat, v.vcIssuerURL)

	vcResp, err := httputil.SendHTTPRequest(v.httpClient, http.MethodPost, endpoint, vcReq, http.StatusCreated,
		v.vcRequestTokens[vcsIssuerRequestTokenName])
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

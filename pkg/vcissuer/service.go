/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcissuer

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package vcissuer_test -source=service.go -mock_names httpClient=MockHTTPClient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	vcprofile "github.com/trustbloc/ace/pkg/doc/vc/profile"
	"github.com/trustbloc/ace/pkg/internal/httputil"
	issueroperation "github.com/trustbloc/ace/pkg/restapi/issuer/operation"
)

const (
	issueCredentialURLFormat     = "%s/%s/credentials/issue" //nolint:gosec
	createIssuerProfileURLFormat = "%s/profile"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config represents configuration parameters for Service.
type Config struct {
	VCIssuerURL    string
	AuthToken      string
	ProfileName    string
	DocumentLoader ld.DocumentLoader
	HTTPClient     httpClient
}

// Service is a service to issue verifiable credentials.
type Service struct {
	vcIssuerURL    string
	authToken      string
	profileName    string
	documentLoader ld.DocumentLoader
	httpClient     httpClient
}

// New creates a new instance of issuer Service.
func New(config *Config) *Service {
	return &Service{
		vcIssuerURL:    config.VCIssuerURL,
		authToken:      config.AuthToken,
		profileName:    config.ProfileName,
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

	resp, err := httputil.DoRequest(ctx, fmt.Sprintf(issueCredentialURLFormat, s.vcIssuerURL, s.profileName),
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

// CreateIssuerProfile create gatekeeper profile on vs issuer service.
func (s *Service) CreateIssuerProfile(
	ctx context.Context, did, publicKeyID string, privateKey ed25519.PrivateKey) error {
	profileRequest := issueroperation.ProfileRequest{}

	profileRequest.Name = s.profileName
	profileRequest.URI = "http://example.com"
	profileRequest.SignatureType = "Ed25519Signature2018"
	profileRequest.DID = did
	profileRequest.DIDPrivateKey = base58.Encode(privateKey)
	profileRequest.DIDKeyID = fmt.Sprintf("%s#%s", did, publicKeyID)
	profileRequest.SignatureRepresentation = 1
	profileRequest.DIDKeyType = "Ed25519"

	req, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := httputil.DoRequest(ctx, fmt.Sprintf(createIssuerProfileURLFormat, s.vcIssuerURL),
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(req),
		httputil.WithHTTPClient(s.httpClient),
		httputil.WithAuthToken(s.authToken))
	if err != nil {
		return fmt.Errorf("create issuer profile request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create issuer profile response status: %d, %s", resp.StatusCode, resp.Body)
	}

	profileResponse := vcprofile.IssuerProfile{}

	err = json.Unmarshal(resp.Body, &profileResponse)
	if err != nil {
		return err
	}

	if did != profileResponse.DID {
		return fmt.Errorf("DID not saved in the profile - expected=%s actual=%s", did, profileResponse.DID)
	}

	return err
}

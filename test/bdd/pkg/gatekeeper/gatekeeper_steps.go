/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/square/go-jose/v3"

	compclient "github.com/trustbloc/ace/pkg/client/comparator/client"
	compoperations "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodels "github.com/trustbloc/ace/pkg/client/comparator/models"
	vcprofile "github.com/trustbloc/ace/pkg/doc/vc/profile"
	issueroperation "github.com/trustbloc/ace/pkg/restapi/issuer/operation"
	"github.com/trustbloc/ace/test/bdd/pkg/common"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/httputil"
)

// Steps defines context for Gatekeeper scenario steps.
type Steps struct {
	cs  *common.Steps
	did string
}

// NewSteps returns new Steps context.
func NewSteps(commonSteps *common.Steps) *Steps {
	return &Steps{
		cs: commonSteps,
	}
}

// RegisterSteps registers Gatekeeper scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Gatekeeper is running on "([^"]*)" port "([^"]*)"$`, s.cs.HealthCheck)
	sc.Step(`^Issuer profile "([^"]*)" is created on "([^"]*)" for "([^"]*)"$`, s.createIssuerProfile)
	sc.Step(`^Intake Processor wants to convert "([^"]*)" social media handle into a DID$`, s.setSocialMediaHandle)
	sc.Step(`^a social media handle "([^"]*)" was converted into a DID$`, s.convertIntoDID)
	sc.Step(`^Handler decides to request release of that DID`, s.setDID)
}

func (s *Steps) createIssuerProfile(ctx context.Context, profileName, issuerURL, comparatorURL string) error {
	compConfig, err := s.getComparatorConfig(comparatorURL)
	if err != nil {
		return fmt.Errorf("get comparator config: %w", err)
	}

	keyID, privateKey, err := convertJSONWebKey(compConfig.Key)
	if err != nil {
		return fmt.Errorf("convert JSON web key: %w", err)
	}

	req := issueroperation.ProfileRequest{
		Name:                    profileName,
		URI:                     "http://example.com",
		SignatureType:           "Ed25519Signature2018",
		DIDKeyType:              "Ed25519",
		SignatureRepresentation: 1,
		DID:                     *compConfig.Did,
		DIDPrivateKey:           privateKey,
		DIDKeyID:                fmt.Sprintf("%s#%s", *compConfig.Did, keyID),
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal profile request: %w", err)
	}

	var issuerProfile vcprofile.IssuerProfile

	resp, err := httputil.DoRequest(ctx, issuerURL+"/profile",
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(reqBytes),
		httputil.WithAuthToken("vcs_issuer_rw_token"),
		httputil.WithParsedResponse(&issuerProfile))
	if err != nil {
		return fmt.Errorf("do profile request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status 201 Created, got: %s", resp.Status)
	}

	if *compConfig.Did != issuerProfile.DID {
		return fmt.Errorf("DID was not saved in the profile: expected=%q, actual=%q", *compConfig.Did,
			issuerProfile.DID)
	}

	return err
}

func (s *Steps) getComparatorConfig(comparatorURL string) (*compmodels.Config, error) {
	client := compclient.New(httptransport.NewWithClient(
		comparatorURL,
		compclient.DefaultBasePath,
		[]string{"https"},
		s.cs.HTTPClient,
	), strfmt.Default)

	cc, err := client.Operations.GetConfig(compoperations.NewGetConfigParams().
		WithTimeout(5 * time.Second)) //nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}

	if *cc.Payload.Did == "" {
		return nil, fmt.Errorf("comparator config DID is empty")
	}

	return cc.Payload, nil
}

func convertJSONWebKey(key interface{}) (string, string, error) {
	keyBytes, err := json.Marshal(key.([]interface{})[0])
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	jwk := jose.JSONWebKey{}
	if err = jwk.UnmarshalJSON(keyBytes); err != nil {
		return "", "", fmt.Errorf("unmarshal jwk bytes: %w", err)
	}

	k, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return "", "", fmt.Errorf("key is not ed25519")
	}

	return jwk.KeyID, base58.Encode(k), nil
}

func (s *Steps) setSocialMediaHandle(ctx context.Context, handle string) context.Context {
	return common.ContextWithRequestParams(ctx, struct {
		SocialMediaHandle string
		PolicyID          string
	}{
		SocialMediaHandle: handle,
		PolicyID:          "test_id",
	})
}

func (s *Steps) convertIntoDID(ctx context.Context, handle string) error {
	// TODO: make a call to convert social media handle into a DID
	s.did = "did:example:1234567"

	return nil
}

func (s *Steps) setDID(ctx context.Context) context.Context {
	return common.ContextWithRequestParams(ctx, struct {
		DID string
	}{
		DID: s.did,
	})
}

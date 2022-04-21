/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"text/template"

	"github.com/cucumber/godog"

	"github.com/trustbloc/ace/test/bdd/pkg/common"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/httputil"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/vdrutil"
)

// Steps defines context for Gatekeeper scenario steps.
type Steps struct {
	cs        *common.Steps
	didOwners map[string]string // "did owner name" -> did:orb:...
	policyID  string
}

// NewSteps returns new Steps context.
func NewSteps(commonSteps *common.Steps) *Steps {
	return &Steps{
		cs:        commonSteps,
		didOwners: make(map[string]string),
	}
}

// RegisterSteps registers Gatekeeper scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Gatekeeper is running on "([^"]*)" port "([^"]*)"$`, s.cs.HealthCheck)
	sc.Step(`^did owner with name "([^"]*)"$`, s.createDIDOwner)
	sc.Step(`^policy configuration with ID "([^"]*)"$`, s.createPolicy)
	sc.Step(`^a social media handle "([^"]*)" converted into a DID by "([^"]*)"$`, s.convertIntoDID)
}

func (s *Steps) createDIDOwner(ctx context.Context, name string) (context.Context, error) {
	doc, pk, err := vdrutil.CreateDIDDoc(s.cs.VDR)
	if err != nil {
		return nil, fmt.Errorf("create did doc: %w", err)
	}

	_, err = vdrutil.ResolveDID(s.cs.VDR, doc.ID, 10) //nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("resolve did: %w", err)
	}

	s.didOwners[name] = doc.ID

	return common.ContextWithSigner(ctx, name, &common.RequestSigner{
		PublicKeyID: doc.Authentication[0].VerificationMethod.ID,
		PrivateKey:  pk,
	}), nil
}

func (s *Steps) createPolicy(ctx context.Context, policyID string, policy *godog.DocString) error {
	t, err := template.New("policy").Parse(policy.Content)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, s)
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	resp, err := httputil.DoRequest(ctx, "https://localhost:9014/v1/policy/"+policyID,
		httputil.WithHTTPClient(s.cs.HTTPClient), httputil.WithMethod(http.MethodPut), httputil.WithBody(buf.Bytes()),
		httputil.WithAuthToken("gk_token"))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errMessage := resp.Status

		if resp.Body != nil {
			var errResp errorResponse

			if err = json.Unmarshal(resp.Body, &errResp); err != nil {
				return fmt.Errorf("unmarshal error response: %w", err)
			}

			errMessage = fmt.Sprintf("%s: %s", errMessage, errResp.Message)
		}

		return errors.New(errMessage)
	}

	s.policyID = policyID

	return nil
}

func (s *Steps) convertIntoDID(ctx context.Context, handle, didOwner string) (context.Context, error) {
	req := &protectReq{
		Policy: s.policyID,
		Target: handle,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal protect request: %w", err)
	}

	signer, ok := common.GetSigner(ctx, didOwner)
	if !ok {
		return nil, fmt.Errorf("missing %q signer in context", didOwner)
	}

	var protectResponse protectResp

	resp, err := httputil.DoRequest(ctx, "https://localhost:9014/v1/protect",
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(reqBytes),
		httputil.WithHTTPClient(s.cs.HTTPClient),
		httputil.WithParsedResponse(&protectResponse),
		httputil.WithSigner(signer))
	if err != nil {
		return nil, fmt.Errorf("do protect request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected 200 OK, got: %s", resp.Status)
	}

	return context.WithValue(ctx, "targetDID", protectResponse.DID), nil //nolint:revive,staticcheck
}

// GetDID is a helper function used in template to get DID by owner name.
func (s *Steps) GetDID(didOwner string) string {
	return s.didOwners[didOwner]
}

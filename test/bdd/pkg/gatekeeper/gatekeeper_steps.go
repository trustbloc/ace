/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

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
	sc.Step(`^Intake Processor wants to convert "([^"]*)" social media handle into a DID$`, s.setSocialMediaHandle)
	sc.Step(`^a social media handle "([^"]*)" was converted into a DID$`, s.convertIntoDID)
	sc.Step(`^Handler decides to request release of that DID`, s.setDID)
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

type protectReq struct {
	Policy string `json:"policy"`
	Target string `json:"target"`
}

type protectResp struct {
	DID string `json:"did"`
}

func (s *Steps) convertIntoDID(ctx context.Context, handle string) error {
	req := &protectReq{
		Policy: "containment-policy",
		Target: handle,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal protect request: %w", err)
	}

	var protectResponse protectResp

	resp, err := httputil.DoRequest(ctx, "https://localhost:9014/v1/protect",
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(reqBytes),
		httputil.WithHTTPClient(s.cs.HTTPClient),
		httputil.WithParsedResponse(&protectResponse))
	if err != nil {
		return fmt.Errorf("do protect request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got: %s", resp.Status)
	}

	s.did = protectResponse.DID

	return nil
}

func (s *Steps) setDID(ctx context.Context) context.Context {
	return common.ContextWithRequestParams(ctx, struct {
		DID string
	}{
		DID: s.did,
	})
}

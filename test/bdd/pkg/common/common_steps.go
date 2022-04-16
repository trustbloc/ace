/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net/http"
	"text/template"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/tidwall/gjson"

	"github.com/trustbloc/ace/pkg/httpsig"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/httputil"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/vdrutil"
)

const (
	healthCheckURL = "https://%s:%d/healthcheck"
)

// DIDOwner defines information about did owner.
type DIDOwner struct {
	didDoc     *did.Doc
	privateKey ed25519.PrivateKey
}

// Steps defines context for common scenario steps.
type Steps struct {
	HTTPClient         *http.Client
	VDR                vdrapi.Registry
	responseStatus     string
	responseStatusCode int
	responseBody       []byte

	didOwners map[string]DIDOwner
}

// NewSteps returns new Steps context.
func NewSteps(tlsConfig *tls.Config) (*Steps, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	vdr, err := vdrutil.CreateVDR(httpClient)
	if err != nil {
		return nil, err
	}

	return &Steps{
		HTTPClient: httpClient,
		VDR:        vdr,
		didOwners:  map[string]DIDOwner{},
	}, nil
}

// RegisterSteps registers common scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^an HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	sc.Step(`^an HTTP POST is sent to "([^"]*)"$`, s.httpPost)
	sc.Step(`^an HTTP POST signed by "([^"]*)" is sent to "([^"]*)"$`, s.signedHTTPPost)
	sc.Step(`^an HTTP PUT is sent to "([^"]*)"$`, s.httpPut)
	sc.Step(`^response status is "([^"]*)"$`, s.checkResponseStatus)
	sc.Step(`^response contains "([^"]*)" with value "([^"]*)"$`, s.checkResponseValue)
	sc.Step(`^response contains non-empty "([^"]*)"$`, s.checkNonEmptyResponseValue)

	sc.Step(`^did owner with name "([^"]*)"$`, s.createDidOwner)
}

type healthCheckResponse struct {
	Status string `json:"status"`
}

// HealthCheck checks if service on host:port is up and running.
func (s *Steps) HealthCheck(ctx context.Context, host string, port int) error {
	url := fmt.Sprintf(healthCheckURL, host, port)

	var healthCheckResp healthCheckResponse

	resp, err := httputil.DoRequest(ctx, url, httputil.WithHTTPClient(s.HTTPClient),
		httputil.WithParsedResponse(&healthCheckResp))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = resp.Status
	s.responseBody = resp.Body

	if resp.StatusCode == http.StatusOK && healthCheckResp.Status == "success" {
		return nil
	}

	return fmt.Errorf("health check failed")
}

func (s *Steps) httpGet(ctx context.Context, url string) error {
	resp, err := httputil.DoRequest(ctx, url, httputil.WithHTTPClient(s.HTTPClient))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = resp.Status
	s.responseBody = resp.Body

	return nil
}

func (s *Steps) httpPost(ctx context.Context, url string, docStr *godog.DocString) error {
	return s.httpDo(ctx, http.MethodPost, url, docStr, httputil.WithAuthToken("gk_token"))
}

func (s *Steps) signedHTTPPost(ctx context.Context, didOwnerName, url string, docStr *godog.DocString) error {
	requestSigner, err := s.CreateRequestSigner(didOwnerName)
	if err != nil {
		return err
	}

	return s.httpDo(ctx, http.MethodPost, url, docStr, httputil.WithRequestSigner(requestSigner))
}

func (s *Steps) httpPut(ctx context.Context, url string, docStr *godog.DocString) error {
	return s.httpDo(ctx, http.MethodPut, url, docStr, httputil.WithAuthToken("gk_token"))
}

type requestParamsKey struct{}

// ContextWithRequestParams creates a new context.Context with request params value.
// Later HTTP POST request gets that value under requestParamsKey and prepares request body.
func ContextWithRequestParams(ctx context.Context, params interface{}) context.Context {
	return context.WithValue(ctx, requestParamsKey{}, params)
}

func (s *Steps) httpDo(ctx context.Context, method, url string, docStr *godog.DocString, opts ...httputil.Opt) error {
	var buf bytes.Buffer

	t, err := template.New("request").Parse(docStr.Content)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	err = t.Execute(&buf, ctx.Value(requestParamsKey{}))
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	opts = append(opts, httputil.WithHTTPClient(s.HTTPClient),
		httputil.WithMethod(method), httputil.WithBody(buf.Bytes()))

	resp, err := httputil.DoRequest(ctx, url, opts...)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = resp.Status
	s.responseStatusCode = resp.StatusCode
	s.responseBody = resp.Body

	return nil
}

func (s *Steps) checkResponseStatus(status string) error {
	if s.responseStatus != status {
		return fmt.Errorf("got %q", s.responseStatus)
	}

	return nil
}

func (s *Steps) checkResponseValue(path, value string) error {
	res := gjson.Get(string(s.responseBody), path)

	if res.Str != value {
		return fmt.Errorf("got %q", res.Str)
	}

	return nil
}

func (s *Steps) checkNonEmptyResponseValue(path string) error {
	res := gjson.Get(string(s.responseBody), path)

	if res.Str == "" {
		return fmt.Errorf("got empty value")
	}

	return nil
}

func (s *Steps) createDidOwner(didOwnerName string) error {
	doc, pk, err := vdrutil.CreateDIDDoc(s.VDR)
	if err != nil {
		return fmt.Errorf("did doc creation failed: %w", err)
	}

	_, err = vdrutil.ResolveDID(s.VDR, doc.ID, 10) //nolint:gomnd
	if err != nil {
		return fmt.Errorf("did doc resolution failed: %w", err)
	}

	s.didOwners[didOwnerName] = DIDOwner{
		didDoc:     doc,
		privateKey: pk,
	}

	return nil
}

// CreateRequestSigner creates request signer for given didOwnerName.
func (s *Steps) CreateRequestSigner(didOwnerName string) (func(req *http.Request) error, error) {
	didOwner, ok := s.didOwners[didOwnerName]
	if !ok {
		return nil, fmt.Errorf("invalid did owner name %q", didOwnerName)
	}

	signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), didOwner.privateKey)

	requestSigner := func(req *http.Request) error {
		return signer.SignRequest(didOwner.didDoc.Authentication[0].VerificationMethod.ID, req)
	}

	return requestSigner, nil
}

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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"text/template"

	"github.com/cucumber/godog"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/tidwall/gjson"

	"github.com/trustbloc/ace/pkg/httpsig"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/httputil"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/vdrutil"
)

const (
	healthCheckURL = "https://%s:%d/healthcheck"
)

// Steps defines context for common scenario steps.
type Steps struct {
	HTTPClient         *http.Client
	VDR                vdrapi.Registry
	responseStatus     string
	responseStatusCode int
	responseBody       []byte
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

	return errors.New("health check failure")
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

type contextKey string

// ContextWithSigner returns a new context with a request signer.
func ContextWithSigner(ctx context.Context, name string, signer *RequestSigner) context.Context {
	return context.WithValue(ctx, contextKey(name), signer)
}

// GetSigner gets signer from the context by signer name.
func GetSigner(ctx context.Context, name string) (*RequestSigner, bool) {
	signer, ok := ctx.Value(contextKey(name)).(*RequestSigner)

	return signer, ok
}

func (s *Steps) signedHTTPPost(ctx context.Context, signerName, url string, docStr *godog.DocString) error {
	signer, ok := ctx.Value(contextKey(signerName)).(*RequestSigner)
	if !ok {
		return fmt.Errorf("missing %q signer in context", signerName)
	}

	return s.httpDo(ctx, http.MethodPost, url, docStr, httputil.WithSigner(signer))
}

func (s *Steps) httpPut(ctx context.Context, url string, docStr *godog.DocString) error {
	return s.httpDo(ctx, http.MethodPut, url, docStr, httputil.WithAuthToken("gk_token"))
}

func (s *Steps) httpDo(ctx context.Context, method, url string, docStr *godog.DocString, opts ...httputil.Opt) error {
	var buf bytes.Buffer

	t, err := template.New("request").Parse(docStr.Content)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	err = t.Execute(&buf, ctx)
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

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

func (s *Steps) checkResponseStatus(status string) error {
	if s.responseStatus != status {
		if s.responseBody != nil {
			var errResp errorResponse

			if err := json.Unmarshal(s.responseBody, &errResp); err != nil {
				return fmt.Errorf("unmarshal error response: %w", err)
			}

			return fmt.Errorf("got %q", fmt.Sprintf("%s: %s", s.responseStatus, errResp.Message))
		}

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

// RequestSigner is a signer for HTTP Signatures auth method.
type RequestSigner struct {
	PublicKeyID string
	PrivateKey  ed25519.PrivateKey
}

// Sign signs an HTTP request.
func (s *RequestSigner) Sign(req *http.Request) error {
	signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), s.PrivateKey)

	if err := signer.SignRequest(s.PublicKeyID, req); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	return nil
}

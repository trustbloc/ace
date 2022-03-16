/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/tidwall/gjson"
)

const (
	healthCheckURL  = "https://%s:%d/healthcheck"
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

var logger = log.New("ace-bdd/gatekeeper")

// Steps defines context for Gatekeeper scenario steps.
type Steps struct {
	httpClient         *http.Client
	responseStatus     string
	responseStatusCode int
	responseBody       []byte
}

// NewSteps returns new Steps context.
func NewSteps(tlsConfig *tls.Config) *Steps {
	return &Steps{
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}
}

// RegisterSteps registers Gatekeeper scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Gatekeeper is running on "([^"]*)" port "([^"]*)"$`, s.healthCheck)
	sc.Step(`^Intake Processor wants to convert "([^"]*)" social media handle into a DID$`, s.setSocialMediaHandle)
	sc.Step(`^an HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	sc.Step(`^an HTTP POST is sent to "([^"]*)"$`, s.httpPost)
	sc.Step(`^response status is "([^"]*)"$`, s.checkResponseStatus)
	sc.Step(`^response contains "([^"]*)" with value "([^"]*)"$`, s.checkResponseValue)
	sc.Step(`^response contains non-empty "([^"]*)"$`, s.checkNonEmptyResponseValue)
}

type healthCheckResponse struct {
	Status string `json:"status"`
}

func (s *Steps) healthCheck(ctx context.Context, host string, port int) error {
	url := fmt.Sprintf(healthCheckURL, host, port)

	var resp healthCheckResponse

	if err := s.do(ctx, url, &resp); err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	if s.responseStatusCode == http.StatusOK && resp.Status == "success" {
		return nil
	}

	return fmt.Errorf("health check failed")
}

type requestParamsKey struct{}

type protectRequestParams struct {
	SocialMediaHandle string
	PolicyID          int
}

func (s *Steps) setSocialMediaHandle(ctx context.Context, handle string) context.Context {
	return context.WithValue(ctx, requestParamsKey{}, protectRequestParams{
		SocialMediaHandle: handle,
		PolicyID:          0,
	})
}

func (s *Steps) httpGet(ctx context.Context, url string) error {
	if err := s.do(ctx, url, nil); err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	return nil
}

func (s *Steps) httpPost(ctx context.Context, url string, docStr *godog.DocString) error {
	var buf bytes.Buffer

	t, err := template.New("request").Parse(docStr.Content)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	err = t.Execute(&buf, ctx.Value(requestParamsKey{}))
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	err = s.do(ctx, url, nil, withMethod(http.MethodPost), withBody(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

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

func (s *Steps) do(ctx context.Context, url string, v interface{}, opts ...opt) error {
	op := &options{method: http.MethodGet}

	for _, fn := range opts {
		fn(op)
	}

	req, err := http.NewRequestWithContext(ctx, op.method, url, op.body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Add(contentType, applicationJSON)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	s.responseStatusCode = resp.StatusCode
	s.responseStatus = resp.Status

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	s.responseBody = body

	if v != nil {
		if err = json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("unmarshal response body: %w", err)
		}
	}

	return nil
}

type options struct {
	method string
	body   io.Reader
}

type opt func(*options)

func withBody(val []byte) opt {
	return func(o *options) {
		o.body = bytes.NewBuffer(val)
	}
}

func withMethod(val string) opt {
	return func(o *options) {
		o.method = val
	}
}

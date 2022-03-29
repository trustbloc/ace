/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/square/go-jose/v3"
	"github.com/tidwall/gjson"

	compclient "github.com/trustbloc/ace/pkg/client/comparator/client"
	compoperations "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodels "github.com/trustbloc/ace/pkg/client/comparator/models"
	vcprofile "github.com/trustbloc/ace/pkg/doc/vc/profile"
	issueroperation "github.com/trustbloc/ace/pkg/restapi/issuer/operation"
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
	sc.Step(`^Issuer profile "([^"]*)" is created on "([^"]*)" for "([^"]*)"$`, s.createIssuerProfile)

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

func (s *Steps) getComparatorConfig(comparatorURL string) (*compmodels.Config, error) {
	client := compclient.New(httptransport.NewWithClient(
		comparatorURL,
		compclient.DefaultBasePath,
		[]string{"https"},
		s.httpClient,
	), strfmt.Default)

	cc, err := client.Operations.GetConfig(compoperations.NewGetConfigParams().
		WithTimeout(5 * time.Second)) //nolint:gomnd
	if err != nil {
		return nil, err
	}

	if *cc.Payload.Did == "" {
		return nil, fmt.Errorf("comparator config DID is empty")
	}

	return cc.Payload, nil
}

func convertJSONWebKey(key interface{}) (string, string, error) {
	keyBytes, err := json.Marshal(key.([]interface{})[0])
	if err != nil {
		return "", "", fmt.Errorf("convert json web key: json marshal failed: %w", err)
	}

	jwk := jose.JSONWebKey{}
	if errUnmarshalJSON := jwk.UnmarshalJSON(keyBytes); errUnmarshalJSON != nil {
		return "", "", fmt.Errorf("failed to unmarshal resp to jwk: %w", errUnmarshalJSON)
	}

	k, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return "", "", fmt.Errorf("key is not ed25519")
	}

	return jwk.KeyID, base58.Encode(k), nil
}

func (s *Steps) createIssuerProfile(profileName, issuerURL, comparatorURL string) error {
	profileRequest := issueroperation.ProfileRequest{}

	compConfig, err := s.getComparatorConfig(comparatorURL)
	if err != nil {
		return err
	}

	keyID, privateKey, err := convertJSONWebKey(compConfig.Key)
	if err != nil {
		return err
	}

	profileRequest.Name = profileName
	profileRequest.URI = "http://example.com"
	profileRequest.SignatureType = "Ed25519Signature2018"
	profileRequest.DID = *compConfig.Did
	profileRequest.DIDPrivateKey = privateKey
	profileRequest.DIDKeyID = fmt.Sprintf("%s#%s", *compConfig.Did, keyID)
	profileRequest.SignatureRepresentation = 1
	profileRequest.DIDKeyType = "Ed25519"

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := httpDo(http.MethodPost, issuerURL+"/profile", "", "vcs_issuer_rw_token",
		bytes.NewBuffer(requestBytes))
	if err != nil {
		return err
	}

	defer closeResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return expectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := vcprofile.IssuerProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	if *compConfig.Did != profileResponse.DID {
		return fmt.Errorf("DID not saved in the profile - expected=%s actual=%s", *compConfig.Did, profileResponse.DID)
	}

	return err
}

func expectedStatusCodeError(expected, actual int, respBytes []byte) error {
	return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
		expected, actual, respBytes)
}

func closeResponseBody(respBody io.Closer) {
	if err := respBody.Close(); err != nil {
		logger.Errorf("Failed to close response body: %s", err.Error())
	}
}

func httpDo(method, url, contentType, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	return http.DefaultClient.Do(req)
}

type requestParamsKey struct{}

type protectRequestParams struct {
	SocialMediaHandle string
	PolicyID          string
}

func (s *Steps) setSocialMediaHandle(ctx context.Context, handle string) context.Context {
	return context.WithValue(ctx, requestParamsKey{}, protectRequestParams{
		SocialMediaHandle: handle,
		PolicyID:          "test_id",
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
		return fmt.Errorf("got %q with %s", s.responseStatus, string(s.responseBody))
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

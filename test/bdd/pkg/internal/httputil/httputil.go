/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
	authorization   = "Authorization"
)

var logger = log.New("ace-bdd")

// Response is an HTTP response.
type Response struct {
	Status     string
	StatusCode int
	Body       []byte
}

// DoRequest makes an HTTP request.
func DoRequest(ctx context.Context, url string, opts ...Opt) (*Response, error) {
	op := &options{
		httpClient: http.DefaultClient,
		method:     http.MethodGet,
	}

	for _, fn := range opts {
		fn(op)
	}

	req, err := http.NewRequestWithContext(ctx, op.method, url, op.body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Add(contentType, applicationJSON)

	if op.token != "" {
		req.Header.Add(authorization, "Bearer "+op.token)
	}

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	r := &Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	r.Body = body

	if op.parsedResponse != nil {
		if err = json.Unmarshal(body, op.parsedResponse); err != nil {
			return nil, fmt.Errorf("unmarshal response body: %w", err)
		}
	}

	return r, nil
}

type options struct {
	httpClient     *http.Client
	method         string
	body           io.Reader
	token          string
	parsedResponse interface{}
}

// Opt configures HTTP request options.
type Opt func(*options)

// WithHTTPClient specifies the custom HTTP client.
func WithHTTPClient(c *http.Client) Opt {
	return func(o *options) {
		o.httpClient = c
	}
}

// WithMethod specifies an HTTP method. Default is GET.
func WithMethod(val string) Opt {
	return func(o *options) {
		o.method = val
	}
}

// WithBody specifies HTTP request body.
func WithBody(val []byte) Opt {
	return func(o *options) {
		o.body = bytes.NewBuffer(val)
	}
}

// WithAuthToken specifies an authorization token.
func WithAuthToken(token string) Opt {
	return func(o *options) {
		o.token = token
	}
}

// WithParsedResponse specifies type to unmarshal response body.
func WithParsedResponse(r interface{}) Opt {
	return func(o *options) {
		o.parsedResponse = r
	}
}
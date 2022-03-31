/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httputil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	contentType     = "Content-Type"
	authorization   = "Authorization"
	applicationJSON = "application/json"
)

var logger = log.New("ace")

// Response is an HTTP response.
type Response struct {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       body,
	}, nil
}

type options struct {
	httpClient httpClient
	method     string
	body       io.Reader
	token      string
}

// Opt configures HTTP request options.
type Opt func(*options)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient specifies the custom HTTP client.
func WithHTTPClient(c httpClient) Opt {
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

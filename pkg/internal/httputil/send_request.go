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
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SendHTTPRequest utility function to send a http request.
// It implements general error handling logic and read of the request body.
func SendHTTPRequest(httpClient httpClient, method, endpoint string, reqBody []byte, status int, httpToken string,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	if httpToken != "" {
		req.Header.Add("Authorization", "Bearer "+httpToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close() // nolint: errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for status: %d", resp.StatusCode)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

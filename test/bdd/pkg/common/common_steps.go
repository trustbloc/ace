/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/tidwall/gjson"

	bddcontext "github.com/trustbloc/ace/test/bdd/pkg/context"
	"github.com/trustbloc/ace/test/bdd/pkg/internal/bddutil"
)

const (
	serverEndpoint = "https://%s:%d"
	contentType    = "application/json"
)

var logger = log.New("ace-bdd/common")

// Steps is steps for BDD tests.
type Steps struct {
	bddContext *bddcontext.BDDContext
	queryValue string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *bddcontext.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^an HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	sc.Step(`^the JSON path "([^"]*)" of the response equals "([^"]*)"$`, s.checkJSONResponse)
	sc.Step(`^Gatekeeper is running on "([^"]*)" port "([^"]*)"$`, s.checkGatekeeperIsRun)
}

// httpGet sends a GET request to the given URL.
func (s *Steps) httpGet(url string) error {
	s.queryValue = ""

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig}}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, errClose)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body failed: %w", err)
	}

	s.queryValue = string(payload)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d", resp.StatusCode)
	}

	return nil
}

func (s *Steps) checkJSONResponse(path, expected string) error {
	r := gjson.Get(s.queryValue, path)

	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}

func (s *Steps) checkGatekeeperIsRun(host string, port int) error {
	_, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	return nil
}

func (s *Steps) healthCheck(host string, port int) (string, error) {
	url := fmt.Sprintf(serverEndpoint, host, port)

	headers := map[string]string{
		"Content-Type": contentType,
	}

	resp, err := bddutil.HTTPDo(http.MethodGet, url+"/healthcheck", headers, nil, s.bddContext.TLSConfig)
	if err != nil {
		return "", err
	}

	err = resp.Body.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err)
	}

	return url, nil
}

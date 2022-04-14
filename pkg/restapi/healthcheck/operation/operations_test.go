/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/handler"
	"github.com/trustbloc/ace/pkg/restapi/healthcheck/operation"
)

func TestGetRESTHandlers(t *testing.T) {
	c := operation.New()
	require.Equal(t, 1, len(c.GetRESTHandlers()))
}

func TestHealthCheck(t *testing.T) {
	c := operation.New()

	b := &httptest.ResponseRecorder{}

	var hndl handler.Handler

	for _, h := range c.GetRESTHandlers() {
		if h.Path() == "/healthcheck" {
			hndl = h
		}
	}

	require.NotNil(t, hndl)
	hndl.Handle()(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

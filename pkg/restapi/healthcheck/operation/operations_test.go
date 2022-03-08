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

	"github.com/trustbloc/ace/pkg/internal/common/support"
	"github.com/trustbloc/ace/pkg/restapi/healthcheck/operation"
)

func TestGetRESTHandlers(t *testing.T) {
	c := operation.New()
	require.Equal(t, 1, len(c.GetRESTHandlers()))
}

func TestHealthCheck(t *testing.T) {
	c := operation.New()

	b := &httptest.ResponseRecorder{}

	var handler support.Handler

	for _, h := range c.GetRESTHandlers() {
		if h.Path() == "/healthcheck" {
			handler = h
		}
	}

	require.NotNil(t, handler)
	handler.Handle()(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

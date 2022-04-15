/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tokenauth_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/mw/tokenauth"
)

func TestMiddleware(t *testing.T) {
	t.Run("auth success", func(t *testing.T) {
		handler := &handler{}

		mw := tokenauth.New("test_tkn")

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Authorization", "Bearer test_tkn")

		mw(handler).ServeHTTP(rw, req)
		require.True(t, handler.executed)
	})

	t.Run("auth failed", func(t *testing.T) {
		handler := &handler{}

		mw := tokenauth.New("test_tkn")

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Authorization", "Bearer test_tkn1")

		mw(handler).ServeHTTP(rw, req)
		require.False(t, handler.executed)
	})
}

type handler struct {
	executed         bool
	requestsCaptured []*http.Request
}

func (h *handler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.executed = true
	h.requestsCaptured = append(h.requestsCaptured, r)
}

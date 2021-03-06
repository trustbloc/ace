/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/handler"
)

func TestNewHTTPHandler(t *testing.T) {
	path := "/sample-path"
	method := "GET"
	handled := make(chan bool)
	handlerFn := func(w http.ResponseWriter, r *http.Request) {
		// do nothing
		handled <- true
	}

	h := handler.NewHTTPHandler(path, method, handlerFn)
	require.Equal(t, path, h.Path())
	require.Equal(t, method, h.Method())
	require.NotNil(t, h.Handle())

	go h.Handle()(nil, nil)

	select {
	case res := <-handled:
		require.True(t, res)
	case <-time.After(2 * time.Second):
		t.Fatal("handler function didn't get executed")
	}
}

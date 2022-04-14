/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"net/http"
)

// Auth handler auth type.
type Auth int

const (
	// AuthNone no auth.
	AuthNone Auth = iota
	// AuthHTTPSig http sig auth.
	AuthHTTPSig
	// AuthToken static token.
	AuthToken
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
	Auth() Auth
}

// NewHTTPHandler returns instance of HTTPHandler which can be used to handle http requests.
func NewHTTPHandler(path, method string, handle http.HandlerFunc, opts ...HTTPHandlerOpts) *HTTPHandler {
	options := &httpHandlerOpts{
		auth: AuthNone,
	}

	for _, opt := range opts {
		opt(options)
	}

	return &HTTPHandler{path: path, method: method, handle: handle, auth: options.auth}
}

// HTTPHandler contains REST API handling details which can be used to build routers
// for http requests for given path.
type HTTPHandler struct {
	path   string
	method string
	handle http.HandlerFunc
	auth   Auth
}

// Path returns http request path.
func (h *HTTPHandler) Path() string {
	return h.path
}

// Method returns http request method type.
func (h *HTTPHandler) Method() string {
	return h.method
}

// Handle returns http request handle func.
func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}

// Auth returns http request auth type.
func (h *HTTPHandler) Auth() Auth {
	return h.auth
}

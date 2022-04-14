/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

type httpHandlerOpts struct {
	auth Auth
}

// HTTPHandlerOpts are the http handler additional options.
type HTTPHandlerOpts func(opts *httpHandlerOpts)

// WithAuth option enable auth for http handler.
func WithAuth(auth Auth) HTTPHandlerOpts {
	return func(opts *httpHandlerOpts) {
		opts.auth = auth
	}
}

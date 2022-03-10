/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"

	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
)

// BDDContext is a global context shared between different test suites in bdd tests.
type BDDContext struct {
	TLSConfig *tls.Config
}

// NewBDDContext creates a new BDD context.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	var tlsConfig *tls.Config

	if caCertPath != "" {
		rootCAs, err := tlsutil.GetCertPool(false, []string{caCertPath})
		if err != nil {
			return nil, err
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		}
	}

	return &BDDContext{
		TLSConfig: tlsConfig,
	}, nil
}

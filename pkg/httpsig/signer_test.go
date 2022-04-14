/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/httpsig"
)

const dateHeader = "Date"

func TestSigner(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("GET", func(t *testing.T) {
		s := httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), privKey)

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, "https://domain1.com", http.NoBody)
		require.NoError(t, err)

		require.NoError(t, s.SignRequest("pubKeyID", req))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("POST", func(t *testing.T) {
		s := httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), privKey)

		payload := []byte("payload")

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, s.SignRequest("pubKeyID", req))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Digest"])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("Signer error", func(t *testing.T) {
		s := httpsig.NewSigner(httpsig.SignerConfig{
			Headers: []string{""},
		}, privKey)

		payload := []byte("payload")

		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		err = s.SignRequest("pubKeyID", req)
		require.Error(t, err)
	})
}

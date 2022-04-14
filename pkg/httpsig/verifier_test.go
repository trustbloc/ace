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
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	verifier2 "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/httpsig"
)

func TestNewVerifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	resolver := NewMockKeyResolver(ctrl)

	v := httpsig.NewVerifier(resolver)
	require.NotNil(t, v)
}

func TestVerifier_VerifyRequest(t *testing.T) {
	const subject = "did:orb:12345667"

	const pubKeyID = subject + "#key-id"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), privKey)
	require.NotNil(t, signer)

	payload := []byte("payload")

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockKeyResolver(ctrl)

		resolver.EXPECT().Resolve(gomock.Any()).Return(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		v := httpsig.NewVerifier(resolver)

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)
		require.NoError(t, signer.SignRequest(pubKeyID, req))

		ok, subjectDid := v.VerifyRequest(req)
		require.True(t, ok)
		require.Equal(t, subjectDid, subject)
	})

	t.Run("Failed verification", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockKeyResolver(ctrl)

		v := httpsig.NewVerifier(resolver)

		resolver.EXPECT().Resolve(gomock.Any()).Return(nil, fmt.Errorf("resolve error"))

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(pubKeyID, req))

		ok, subjectDid := v.VerifyRequest(req)
		require.False(t, ok)
		require.Equal(t, "", subjectDid)
	})

	t.Run("Key ID not found in signature header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockKeyResolver(ctrl)

		resolver.EXPECT().Resolve(gomock.Any()).Times(0)

		v := httpsig.NewVerifier(resolver)

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		req.Header["Signature"] = []string{}

		ok, subjectDid := v.VerifyRequest(req)
		require.False(t, ok)
		require.Equal(t, "", subjectDid)
	})

	t.Run("Invalid key ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockKeyResolver(ctrl)

		resolver.EXPECT().Resolve(gomock.Any()).Return(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		v := httpsig.NewVerifier(resolver)

		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)
		require.NoError(t, signer.SignRequest("invalid", req))

		ok, subjectDid := v.VerifyRequest(req)
		require.False(t, ok)
		require.Equal(t, "", subjectDid)
	})
}

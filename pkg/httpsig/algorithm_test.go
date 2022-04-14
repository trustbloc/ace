/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	verifier2 "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/httpsig"
)

func TestSignatureHashAlgorithm_Create(t *testing.T) {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	algo := httpsig.NewSignerAlgorithm(pk)
	require.NotNil(t, algo)
	require.Equal(t, "Ed25519", algo.Algorithm())

	secret := httpsignatures.Secret{}

	data := []byte("data")

	t.Run("Success", func(t *testing.T) {
		signature, err := algo.Create(secret, data)
		require.NoError(t, err)
		require.NotNil(t, signature)
	})
}

func TestSignatureHashAlgorithm_Verify(t *testing.T) {
	const pubKeyID = "did:orb:12345667#key-id"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	resolver := NewMockKeyResolver(ctrl)

	algo := httpsig.NewVerifierAlgorithm(resolver)
	require.NotNil(t, algo)
	require.Equal(t, "Ed25519", algo.Algorithm())

	secret := httpsignatures.Secret{
		KeyID: pubKeyID,
	}

	data := []byte("data")

	signature := ed25519.Sign(privKey, data)

	t.Run("Success", func(t *testing.T) {
		resolver.EXPECT().Resolve(gomock.Any()).Return(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		require.NoError(t, algo.Verify(secret, data, signature))
	})

	t.Run("Invalid signature", func(t *testing.T) {
		resolver.EXPECT().Resolve(gomock.Any()).Return(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		err := algo.Verify(secret, data, []byte("invalid signature"))
		require.Error(t, err)
		require.True(t, errors.Is(err, httpsig.ErrInvalidSignature))
	})

	t.Run("ResolveKey error", func(t *testing.T) {
		errExpected := errors.New("injected resolver error")

		resolver.EXPECT().Resolve(gomock.Any()).Return(nil, errExpected)

		err := algo.Verify(secret, data, signature)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

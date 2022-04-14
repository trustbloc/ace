/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsigmw_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/doc/vc/crypto"
	"github.com/trustbloc/ace/pkg/httpsig"
	"github.com/trustbloc/ace/pkg/restapi/mw/httpsigmw"
)

func TestMiddleware(t *testing.T) {
	t.Run("protects endpoints", func(t *testing.T) {
		handler := &handler{}

		didDoc, pk, err := newDIDDoc()
		require.NoError(t, err)

		cfg := &httpsigmw.Config{VDR: &vdr.MockVDRegistry{
			ResolveValue: didDoc,
		}}
		mw := httpsigmw.New(cfg)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Test", "Test")

		signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), pk)
		err = signer.SignRequest(didDoc.Authentication[0].VerificationMethod.ID, req)
		require.NoError(t, err)

		mw(handler).ServeHTTP(rw, req)
		require.True(t, handler.executed)

		subjectDID, ok := httpsigmw.SubjectDID(handler.requestsCaptured[0].Context())
		require.True(t, ok)
		require.Equal(t, didDoc.ID, subjectDID)
	})

	t.Run("did resolve error", func(t *testing.T) {
		handler := &handler{}

		didDoc, pk, err := newDIDDoc()
		require.NoError(t, err)

		cfg := &httpsigmw.Config{VDR: &vdr.MockVDRegistry{
			ResolveErr: errors.New("did resolve error"),
		}}
		mw := httpsigmw.New(cfg)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Test", "Test")

		signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), pk)
		err = signer.SignRequest(didDoc.Authentication[0].VerificationMethod.ID, req)
		require.NoError(t, err)

		mw(handler).ServeHTTP(rw, req)

		require.False(t, handler.executed)
	})

	t.Run("key id mismatch auth", func(t *testing.T) {
		handler := &handler{}

		didDoc, pk, err := newDIDDoc()
		require.NoError(t, err)

		cfg := &httpsigmw.Config{VDR: &vdr.MockVDRegistry{
			ResolveValue: didDoc,
		}}
		mw := httpsigmw.New(cfg)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Test", "Test")

		signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), pk)
		err = signer.SignRequest("did:orb:123456#wrong-key-id", req)
		require.NoError(t, err)

		mw(handler).ServeHTTP(rw, req)

		require.False(t, handler.executed)
	})

	t.Run("invalid key id", func(t *testing.T) {
		handler := &handler{}

		didDoc, pk, err := newDIDDoc()
		require.NoError(t, err)

		cfg := &httpsigmw.Config{VDR: &vdr.MockVDRegistry{
			ResolveValue: didDoc,
		}}
		mw := httpsigmw.New(cfg)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http:/example.com/test", bytes.NewBuffer([]byte("Test Body")))
		req.Header.Add("Test", "Test")

		signer := httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), pk)
		err = signer.SignRequest("invalid-key-id", req)
		require.NoError(t, err)

		mw(handler).ServeHTTP(rw, req)

		require.False(t, handler.executed)
	})
}

func newDIDDoc() (*did.Doc, ed25519.PrivateKey, error) {
	didDoc := &did.Doc{
		ID: "did:orb:test123456",
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	keyID := uuid.New().String()

	jwk, err := jwksupport.JWKFromKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	vm, err := did.NewVerificationMethodFromJWK(didDoc.ID+"#"+keyID, crypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, nil, err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	return didDoc, privateKey, nil
}

type handler struct {
	executed         bool
	requestsCaptured []*http.Request
}

func (h *handler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.executed = true
	h.requestsCaptured = append(h.requestsCaptured, r)
}

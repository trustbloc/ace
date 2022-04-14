/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package httpsig_test -source=algorithm.go -mock_names keyResolver=MockKeyResolver

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	ariesverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	httpsig "github.com/igor-pavlenko/httpsignatures-go"
)

const aceHTTPSigAlgorithm = "Ed25519"

// ErrInvalidSignature indicates that the signature is not valid for the given data.
var ErrInvalidSignature = errors.New("invalid HTTP signature")

type keyResolver interface {
	// Resolve returns the public key bytes and the type of public key for the given key ID.
	Resolve(keyID string) (*ariesverifier.PublicKey, error)
}

// SignatureHashAlgorithm is a custom httpsignatures.SignatureHashAlgorithm that uses ed25519 key to sign HTTP requests.
type SignatureHashAlgorithm struct {
	pubKeyResolver keyResolver
	privateKey     ed25519.PrivateKey
}

// NewSignerAlgorithm returns a new SignatureHashAlgorithm which uses ed25519 key to sign HTTP requests.
func NewSignerAlgorithm(privateKey ed25519.PrivateKey) *SignatureHashAlgorithm {
	return &SignatureHashAlgorithm{
		privateKey: privateKey,
	}
}

// NewVerifierAlgorithm returns a new SignatureHashAlgorithm which is used to verify the signature
// in the HTTP request header.
func NewVerifierAlgorithm(pubKeyResolver keyResolver) *SignatureHashAlgorithm {
	return &SignatureHashAlgorithm{
		pubKeyResolver: pubKeyResolver,
	}
}

// Algorithm returns this algorithm's name.
func (a *SignatureHashAlgorithm) Algorithm() string {
	return aceHTTPSigAlgorithm
}

// Create signs data with the secret.
func (a *SignatureHashAlgorithm) Create(_ httpsig.Secret, data []byte) ([]byte, error) {
	return ed25519.Sign(a.privateKey, data), nil
}

// Verify verifies the signature over data with the secret.
func (a *SignatureHashAlgorithm) Verify(secret httpsig.Secret, data, signature []byte) error {
	pubKey, err := a.pubKeyResolver.Resolve(secret.KeyID)
	if err != nil {
		return fmt.Errorf("resolve key %s: %w", secret.KeyID, err)
	}

	logger.Debugf("Got key %+v from keyID [%s]", pubKey, secret.KeyID)

	if !ed25519.Verify(pubKey.Value, data, signature) {
		logger.Infof("Signature verification failed using keyID [%s]", secret.KeyID)

		return ErrInvalidSignature
	}

	logger.Debugf("Successfully verified signature using keyID [%s]", secret.KeyID)

	return nil
}

// SecretRetriever implements a custom key retriever to be used with the HTTP signature library.
type SecretRetriever struct{}

// Get returns a 'secret' that directs the HTTP signature library to use the custom SignatureHashAlgorithm above.
func (r *SecretRetriever) Get(keyID string) (httpsig.Secret, error) {
	return httpsig.Secret{
		KeyID:     keyID,
		Algorithm: aceHTTPSigAlgorithm,
	}, nil
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"net/http"
	"strings"

	httpsig "github.com/igor-pavlenko/httpsignatures-go"
)

type verifier interface {
	Verify(r *http.Request) error
}

// Verifier verifies signatures of HTTP requests.
type Verifier struct {
	verifier func() verifier
}

// NewVerifier returns a new HTTP signature verifier.
func NewVerifier(pubKeyResolver keyResolver) *Verifier {
	algo := NewVerifierAlgorithm(pubKeyResolver)
	secretRetriever := &SecretRetriever{}

	return &Verifier{
		verifier: func() verifier {
			// Return a new instance for each verification since the HTTP signature
			// implementation is not thread safe.
			hs := httpsig.NewHTTPSignatures(secretRetriever)
			hs.SetSignatureHashAlgorithm(algo)

			return hs
		},
	}
}

// VerifyRequest verifies the following:
// - HTTP signature on the request.
//
// Returns:
// - true if the signature was successfully verified, otherwise false.
// - Subject DID if the signature was successfully verified.
func (v *Verifier) VerifyRequest(req *http.Request) (bool, string) {
	logger.Debugf("Verifying request. Headers: %s", req.Header)

	err := v.verifier().Verify(req)
	if err != nil {
		logger.Infof("Signature verification failed for request %s: %s", req.URL, err)

		return false, ""
	}

	keyID := getKeyIDFromSignatureHeader(req)
	keyIDParts := strings.Split(keyID, "#")

	if len(keyIDParts) != 2 { //nolint:gomnd
		logger.Debugf("'keyId' has invalid format %s", keyID)

		return false, ""
	}

	logger.Debugf("Successfully verified signature in header. KeyId [%s]", keyID)

	return true, keyIDParts[0]
}

func getKeyIDFromSignatureHeader(req *http.Request) string {
	signatureHeader, ok := req.Header["Signature"]
	if !ok || len(signatureHeader) == 0 {
		logger.Debugf("'Signature' not found in request header for request %s", req.URL)

		return ""
	}

	var keyID string

	const kvLength = 2

	for _, v := range signatureHeader {
		for _, kv := range strings.Split(v, ",") {
			parts := strings.Split(kv, "=")
			if len(parts) != kvLength {
				continue
			}

			if parts[0] == "keyId" {
				keyID = strings.ReplaceAll(parts[1], `"`, "")
			}
		}
	}

	return keyID
}

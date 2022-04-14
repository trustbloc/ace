/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsigmw

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"

	"github.com/trustbloc/ace/pkg/httpsig"
)

const (
	unauthorizedResponse = "Unauthorized.\n"
)

var contextKeySubjectDID = contextKey("subject-did") //nolint:gochecknoglobals

var logger = log.New("httpsig-middleware")

type vdrRegistry interface {
	Resolve(DID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

// Config used to configure httpsig auth middleware.
type Config struct {
	VDR vdrRegistry
}

type mwHandler struct {
	next http.Handler
	vdr  vdrRegistry
}

type contextKey string

// SubjectDID reads subject did from context.
func SubjectDID(ctx context.Context) (string, bool) {
	subjectDID, ok := ctx.Value(contextKeySubjectDID).(string)

	return subjectDID, ok
}

// New returns httpsig auth middleware.
func New(cfg *Config) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return &mwHandler{
			next: h,
			vdr:  cfg.VDR,
		}
	}
}

func (h *mwHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signVerifier := httpsig.NewVerifier(&pubKeyResolver{
		vdr: h.vdr,
	})

	verified, subjectDID := signVerifier.VerifyRequest(r)
	if !verified {
		w.WriteHeader(http.StatusUnauthorized)

		if _, err := w.Write([]byte(unauthorizedResponse)); err != nil {
			logger.Warnf("[%s] Unable to write response: %s", r.URL, err)
		}

		return
	}

	ctx := context.WithValue(r.Context(), contextKeySubjectDID, subjectDID)

	h.next.ServeHTTP(w, r.WithContext(ctx))
}

type pubKeyResolver struct {
	vdr vdrRegistry
}

func (r *pubKeyResolver) Resolve(keyID string) (*verifier.PublicKey, error) {
	keyIDParts := strings.Split(keyID, "#")

	if len(keyIDParts) != 2 { //nolint:gomnd
		return nil, fmt.Errorf("invalid pub key format %s", keyID)
	}

	subjectDID := keyIDParts[0]

	docResolution, err := r.vdr.Resolve(subjectDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", subjectDID, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods(did.Authentication) {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) {
				return &verifier.PublicKey{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", keyID, subjectDID)
}

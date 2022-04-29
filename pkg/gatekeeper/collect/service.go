/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package collect

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package collect_test -source=service.go -mock_names vaultClient=MockVault,comparatorClient=MockComparator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trustbloc/edge-core/pkg/zcapld"

	compclientops "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodel "github.com/trustbloc/ace/pkg/client/comparator/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

const (
	requestTimeout = 30 * time.Second
	authExpiryTime = 5 * time.Minute
)

type comparatorClient interface {
	GetConfig(params *compclientops.GetConfigParams, opts ...compclientops.ClientOption) (*compclientops.GetConfigOK, error)                            //nolint:lll
	PostAuthorizations(params *compclientops.PostAuthorizationsParams, opts ...compclientops.ClientOption) (*compclientops.PostAuthorizationsOK, error) //nolint:lll
}

type vaultClient interface {
	CreateAuthorization(vaultID, requestingParty string,
		scope *vault.AuthorizationsScope) (*vault.CreatedAuthorization, error)
}

// Service is a service for collecting protected resources.
type Service struct {
	compClient comparatorClient
	vClient    vaultClient
}

// NewService returns new collect service.
func NewService(compClient comparatorClient, vClient vaultClient) *Service {
	return &Service{
		compClient: compClient,
		vClient:    vClient,
	}
}

// Collect collects protected resource and returns access handle for it.
func (s *Service) Collect(
	_ context.Context, protectedData *protect.ProtectedData, requestingPartyDID string) (string, error) {
	compConfig, err := s.getComparatorConfig()
	if err != nil {
		return "", fmt.Errorf("failed get config from comparator: %w", err)
	}

	auth, err := s.getAuthorization(
		protectedData.DID,
		compConfig.AuthKeyURL,
		protectedData.VCDocID,
		requestingPartyDID,
	)
	if err != nil {
		return "", fmt.Errorf("failed get authorization: %w", err)
	}

	return auth, nil
}

func (s *Service) getComparatorConfig() (*compmodel.Config, error) {
	confResp, err := s.compClient.GetConfig(compclientops.NewGetConfigParams().
		WithTimeout(requestTimeout))
	if err != nil {
		return nil, fmt.Errorf("get config : %w", err)
	}

	if confResp.Payload == nil {
		return nil, errors.New("empty config from comparator")
	}

	return confResp.Payload, nil
}

func (s *Service) getAuthorization(vaultID, rp, docID, authDID string) (string, error) {
	docAuth, err := s.vClient.CreateAuthorization(
		vaultID,
		rp,
		&vault.AuthorizationsScope{
			Target:  docID,
			Actions: []string{"read"},
			Caveats: []vault.Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: uint64(authExpiryTime)}},
		},
	)
	if err != nil {
		return "", fmt.Errorf("create vault authorization : %w", err)
	}

	if docAuth == nil || docAuth.Tokens == nil {
		return "", errors.New("missing auth token from vault-server")
	}

	scope := &compmodel.Scope{
		Actions:     []string{"extract"},
		VaultID:     vaultID,
		DocID:       &docID,
		AuthTokens:  &compmodel.ScopeAuthTokens{Edv: docAuth.Tokens.EDV, Kms: docAuth.Tokens.KMS},
		DocAttrPath: "$.credentialSubject.data",
	}

	caveat := make([]compmodel.Caveat, 0)
	caveat = append(caveat, &compmodel.ExpiryCaveat{Duration: int64(authExpiryTime)})

	scope.SetCaveats(caveat)

	authResp, err := s.compClient.PostAuthorizations(
		compclientops.NewPostAuthorizationsParams().
			WithTimeout(requestTimeout).
			WithAuthorization(
				&compmodel.Authorization{
					RequestingParty: &authDID,
					Scope:           scope,
				},
			),
	)
	if err != nil {
		return "", fmt.Errorf("create comparator authorization : %w", err)
	}

	if authResp == nil || authResp.Payload == nil {
		return "", errors.New("missing auth token from comparator")
	}

	return authResp.Payload.AuthToken, nil
}

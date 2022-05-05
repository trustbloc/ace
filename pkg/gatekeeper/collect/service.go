/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package collect

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package collect_test -source=service.go -mock_names vaultClient=MockVault,configService=MockConfigService,cshClient=MockCSHClient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/ace/pkg/client/csh/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/config"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

const (
	requestTimeout = 30 * time.Second
	authExpiryTime = 5 * time.Minute
)

type configService interface {
	Get() (*config.Config, error)
}

type cshClient interface {
	PostHubstoreProfilesProfileIDQueries(params *operations.PostHubstoreProfilesProfileIDQueriesParams,
		opts ...operations.ClientOption) (*operations.PostHubstoreProfilesProfileIDQueriesCreated, error)
}

type vaultClient interface {
	CreateAuthorization(vaultID, requestingParty string,
		scope *vault.AuthorizationsScope) (*vault.CreatedAuthorization, error)
	GetDocMetaData(vaultID, docID string) (*vault.DocumentMetadata, error)
}

// Service is a service for collecting protected resources.
type Service struct {
	configService configService
	vClient       vaultClient
	cshClient     cshClient
}

// NewService returns new collect service.
func NewService(configService configService, vClient vaultClient, cshClient cshClient) *Service {
	return &Service{
		configService: configService,
		vClient:       vClient,
		cshClient:     cshClient,
	}
}

// Collect collects protected resource and returns access handle for it.
func (s *Service) Collect(
	_ context.Context, protectedData *protect.ProtectedData, requestingPartyDID string) (string, error) {
	auth, err := s.createQueryOnCSH(
		protectedData.DID,
		protectedData.VCDocID,
		requestingPartyDID,
	)
	if err != nil {
		return "", fmt.Errorf("failed get authorization: %w", err)
	}

	return auth, nil
}

func (s *Service) createQueryOnCSH(vaultID, docID, _ string) (string, error) { // nolint:funlen
	cfg, err := s.configService.Get()
	if err != nil {
		return "", fmt.Errorf("failed get config: %w", err)
	}

	docAuth, err := s.vClient.CreateAuthorization(
		vaultID,
		cfg.CSHPubKeyURL,
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

	docMeta, err := s.vClient.GetDocMetaData(vaultID, docID)
	if err != nil {
		return "", fmt.Errorf("failed to get doc meta: %w", err)
	}

	kmsURL, err := url.Parse(docMeta.EncKeyURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse enc key uri: %w", err)
	}

	edvURL, err := url.Parse(docMeta.URI)
	if err != nil {
		return "", fmt.Errorf("failed to parse doc uri: %w", err)
	}

	parts := strings.Split(docMeta.URI, "/")
	edvVaultID := parts[len(parts)-3]
	edvDocID := parts[len(parts)-1]

	docAttrPath := "$.credentialSubject.data"

	response, err := s.cshClient.PostHubstoreProfilesProfileIDQueries(
		operations.NewPostHubstoreProfilesProfileIDQueriesParams().
			WithTimeout(requestTimeout).
			WithProfileID(cfg.CSHProfileID).
			WithRequest(&cshclientmodels.DocQuery{
				VaultID: &edvVaultID,
				DocID:   &edvDocID,
				Path:    docAttrPath,
				UpstreamAuth: &cshclientmodels.DocQueryAO1UpstreamAuth{
					Edv: &cshclientmodels.UpstreamAuthorization{
						BaseURL: fmt.Sprintf("%s://%s/%s", edvURL.Scheme, edvURL.Host, parts[3]),
						Zcap:    docAuth.Tokens.EDV,
					},
					Kms: &cshclientmodels.UpstreamAuthorization{
						BaseURL: fmt.Sprintf("%s://%s", kmsURL.Scheme, kmsURL.Host),
						Zcap:    docAuth.Tokens.KMS,
					},
				},
			}))
	if err != nil {
		return "", fmt.Errorf("failed to create query: %w", err)
	}

	queryID := strings.Split(response.Location, "/queries/")[1]

	return queryID, nil
}

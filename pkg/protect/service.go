/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protect

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package protect_test -source=service.go -mock_names vaultClient=MockVault,vdrRegistry=MockVDRRegistry,storage=MockStore,vcIssuer=MockVCIssuer

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/edv/pkg/edvutils"

	"github.com/trustbloc/ace/pkg/restapi/model"
	"github.com/trustbloc/ace/pkg/restapi/vault"
)

const (
	credentialContext = "https://www.w3.org/2018/credentials/v1" //nolint:gosec
	resolveMaxRetry   = 10
)

type vaultClient interface {
	CreateVault() (*vault.CreatedVault, error)
	SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error)
}

type vdrRegistry interface {
	Resolve(DID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

type storage interface {
	Get(hash string) (*model.ProtectedData, error)
	Put(data *model.ProtectedData) error
}

type vcIssuer interface {
	IssueCredential(ctx context.Context, cred []byte) (*verifiable.Credential, error)
}

// Config defines configuration options for Service.
type Config struct {
	Store       storage
	VaultClient vaultClient
	VDR         vdrRegistry
	VCIssuer    vcIssuer
}

// Service is a service for converting sensitive data into DID.
type Service struct {
	store       storage
	vaultClient vaultClient
	vdr         vdrRegistry
	issuer      vcIssuer
}

// NewService creates a new instance of protect.Service.
func NewService(config *Config) *Service {
	return &Service{
		store:       config.Store,
		vaultClient: config.VaultClient,
		vdr:         config.VDR,
		issuer:      config.VCIssuer,
	}
}

// Protect converts target into DID.
func (s *Service) Protect(ctx context.Context, target, policyID string) (string, error) {
	hash, err := calculateHash(target)
	if err != nil {
		return "", fmt.Errorf("calculate hash: %w", err)
	}

	data, err := s.store.Get(hash)
	if err != nil {
		return "", err
	}

	if data != nil {
		return data.DID, nil
	}

	vaultData, err := s.vaultClient.CreateVault()
	if err != nil {
		return "", err
	}

	vaultID := vaultData.ID

	vc, err := s.wrapDataIntoVC(ctx, vaultID, target)
	if err != nil {
		return "", fmt.Errorf("wrap data into vc: %w", err)
	}

	// resolve DID
	err = resolveDID(s.vdr, vaultID, resolveMaxRetry)
	if err != nil {
		return "", fmt.Errorf("resolve did %s : %w", vaultID, err)
	}

	vcDocID, err := s.saveVCDoc(vaultID, vc)
	if err != nil {
		return "", fmt.Errorf("save vc doc: %w", err)
	}

	err = s.store.Put(&model.ProtectedData{
		PolicyID:      policyID,
		Hash:          hash,
		DID:           vaultID,
		TargetVCDocID: vcDocID,
	})

	if err != nil {
		return "", fmt.Errorf("save protected data: %w", err)
	}

	return vaultID, nil
}

func (s *Service) wrapDataIntoVC(ctx context.Context, sub, data string) (*verifiable.Credential, error) {
	if data == "" {
		return nil, errors.New("data is mandatory")
	}

	cred := verifiable.Credential{}
	cred.ID = uuid.New().URN()
	cred.Context = []string{credentialContext}
	cred.Types = []string{"VerifiableCredential"}
	// issuerID will be overwritten in the issuer
	cred.Issuer = verifiable.Issuer{ID: uuid.New().URN()}
	cred.Issued = util.NewTime(time.Now().UTC())

	credentialSubject := make(map[string]interface{})
	credentialSubject["id"] = sub
	credentialSubject["data"] = data

	cred.Subject = credentialSubject

	credBytes, err := cred.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}

	vc, err := s.issuer.IssueCredential(ctx, credBytes)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (s *Service) saveVCDoc(vaultID string, vc *verifiable.Credential) (string, error) {
	docID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return "", fmt.Errorf("create edv doc id : %w", err)
	}

	_, err = s.vaultClient.SaveDoc(vaultID, docID, vc)
	if err != nil {
		return "", fmt.Errorf("failed to save doc : %w", err)
	}

	return docID, nil
}

func calculateHash(data string) (string, error) {
	h := fnv.New128()

	if _, err := h.Write([]byte(data)); err != nil {
		return "", fmt.Errorf("calculate data hash: %w", err)
	}

	return string(h.Sum(nil)), nil
}

func resolveDID(vdrRegistry vdrRegistry, resolveDID string, maxRetry int) error {
	for i := 1; i <= maxRetry; i++ {
		_, err := vdrRegistry.Resolve(resolveDID)
		if err == nil {
			return nil
		}

		if !strings.Contains(err.Error(), "DID does not exist") {
			return err
		}

		if i == maxRetry {
			return fmt.Errorf("resolve did: %w", err)
		}

		fmt.Printf("did %s not found will retry %d of %d\n", resolveDID, i, maxRetry)
		time.Sleep(1 * time.Second)
	}

	return nil
}

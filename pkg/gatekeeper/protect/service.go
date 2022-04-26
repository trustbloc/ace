/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protect

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package protect_test -source=service.go -mock_names vaultClient=MockVault,vdrRegistry=MockVDR,vcIssuer=MockVCIssuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edv/pkg/edvutils"

	"github.com/trustbloc/ace/pkg/restapi/vault"
)

const (
	credentialContext = "https://www.w3.org/2018/credentials/v1" //nolint:gosec
	storeName         = "protected_data"
	resolveMaxRetry   = 10
	policyIndex       = "policyID"
)

var logger = log.New("protect-svc")

type vaultClient interface {
	CreateVault() (*vault.CreatedVault, error)
	SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error)
}

type vdrRegistry interface {
	Resolve(DID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

type vcIssuer interface {
	IssueCredential(ctx context.Context, cred []byte) (*verifiable.Credential, error)
}

// Config defines dependencies for Service.
type Config struct {
	StoreProvider storage.Provider
	VaultClient   vaultClient
	VDR           vdrRegistry
	VCIssuer      vcIssuer
}

// Service is a service for converting sensitive data into DID.
type Service struct {
	store       storage.Store
	vaultClient vaultClient
	vdr         vdrRegistry
	issuer      vcIssuer
}

// NewService returns a new instance of Service.
func NewService(config *Config) (*Service, error) {
	store, err := config.StoreProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open protected data store: %w", err)
	}

	err = config.StoreProvider.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{policyIndex}})
	if err != nil {
		return nil, fmt.Errorf("set protected data store configuration: %w", err)
	}

	return &Service{
		store:       store,
		vaultClient: config.VaultClient,
		vdr:         config.VDR,
		issuer:      config.VCIssuer,
	}, nil
}

// ProtectedData defines the model for protected data.
type ProtectedData struct {
	DID      string `json:"did"`
	VCDocID  string `json:"vc_doc_id,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

// Get gets protected data for target DID.
func (s *Service) Get(_ context.Context, targetDID string) (*ProtectedData, error) {
	iter, err := s.store.Query(policyIndex)
	if err != nil {
		return nil, fmt.Errorf("query protected data: %w", err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("Failed to close iterator: %s", err.Error())
		}
	}()

	for {
		if ok, err := iter.Next(); !ok || err != nil {
			if err != nil {
				return nil, fmt.Errorf("next entry: %w", err)
			}

			break
		}

		v, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("get value: %w", err)
		}

		var data ProtectedData

		if err = json.Unmarshal(v, &data); err != nil {
			return nil, fmt.Errorf("unmarshal data: %w", err)
		}

		if data.DID == targetDID {
			return &data, nil
		}
	}

	return nil, fmt.Errorf("get protected data: %w", storage.ErrDataNotFound)
}

// Protect converts sensitive data into DID.
func (s *Service) Protect(ctx context.Context, target, policyID string) (*ProtectedData, error) {
	hash, err := calculateHash(target)
	if err != nil {
		return nil, fmt.Errorf("calculate hash: %w", err)
	}

	b, err := s.store.Get(hash)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("get protected data by hash: %w", err)
	}

	if b != nil {
		var data ProtectedData

		if err = json.Unmarshal(b, &data); err != nil {
			return nil, fmt.Errorf("unmarshal protected data: %w", err)
		}

		return &data, nil
	}

	vaultData, err := s.vaultClient.CreateVault()
	if err != nil {
		return nil, fmt.Errorf("create vault: %w", err)
	}

	vaultID := vaultData.ID

	vc, err := s.wrapDataIntoVC(ctx, vaultID, target)
	if err != nil {
		return nil, fmt.Errorf("wrap data into vc: %w", err)
	}

	// resolve DID
	err = resolveDID(s.vdr, vaultID, resolveMaxRetry)
	if err != nil {
		return nil, fmt.Errorf("resolve did %s : %w", vaultID, err)
	}

	vcDocID, err := s.saveVCDoc(vaultID, vc)
	if err != nil {
		return nil, fmt.Errorf("save vc doc: %w", err)
	}

	data := ProtectedData{
		DID:      vaultID,
		VCDocID:  vcDocID,
		PolicyID: policyID,
	}

	b, err = json.Marshal(&data)
	if err != nil {
		return nil, fmt.Errorf("marshal protected data: %w", err)
	}

	if err = s.store.Put(hash, b, storage.Tag{Name: policyIndex, Value: data.PolicyID}); err != nil {
		return nil, fmt.Errorf("save protected data: %w", err)
	}

	return &data, nil
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

		time.Sleep(1 * time.Second)
	}

	return nil
}

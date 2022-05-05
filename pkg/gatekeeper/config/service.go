/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package config

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package config_test -source=service.go -mock_names cshClient=MockCSHClient,vdrRegistry=MockVDRRegistry

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/ace/pkg/client/csh/models"
	vccrypto "github.com/trustbloc/ace/pkg/doc/vc/crypto"
)

const (
	configKeyDB    = "config"
	storeName      = "config"
	requestTimeout = 5 * time.Second
)

type cshClient interface {
	PostHubstoreProfiles(params *operations.PostHubstoreProfilesParams,
		opts ...operations.ClientOption) (*operations.PostHubstoreProfilesCreated, error)
}

type vdrRegistry interface {
	Resolve(DID string, opts ...vdr.DIDMethodOption) (*docdid.DocResolution, error)
	Create(method string, DID *docdid.Doc, opts ...vdr.DIDMethodOption) (*docdid.DocResolution, error)
}

// ServiceParams contains parameters of config Service.
type ServiceParams struct {
	StoreProvider   storage.Provider
	CSHClient       cshClient
	VDR             vdrRegistry
	KeyManager      kms.KeyManager
	DidMethod       string
	DidAnchorOrigin string
}

// Service responsible for creating and storing gatekeeper config.
type Service struct {
	store           storage.Store
	cshClient       cshClient
	vdr             vdrRegistry
	keyManager      kms.KeyManager
	didMethod       string
	didAnchorOrigin string
}

// NewService returns a new instance of Service.
func NewService(params *ServiceParams) (*Service, error) {
	store, err := params.StoreProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open policy store: %w", err)
	}

	return &Service{
		store:           store,
		cshClient:       params.CSHClient,
		vdr:             params.VDR,
		keyManager:      params.KeyManager,
		didMethod:       params.DidMethod,
		didAnchorOrigin: params.DidAnchorOrigin,
	}, nil
}

// HasConfig checks if config is stored.
func (s *Service) HasConfig() (bool, error) {
	_, err := s.store.Get(configKeyDB)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("get protected data by hash: %w", err)
	}

	return true, nil
}

// Get returns stored config.
func (s *Service) Get() (*Config, error) {
	b, err := s.store.Get(configKeyDB)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}

	var config Config

	if err = json.Unmarshal(b, &config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &config, nil
}

// CreateConfig creates gatekeeper DID, CSH profile, and store them in Config.
func (s *Service) CreateConfig() error { //nolint: funlen
	// create did
	didDoc, pubKeyID, privateKey, err := s.newPublicKeys()
	if err != nil {
		return fmt.Errorf("failed to create public keys : %w", err)
	}

	recoverKey, err := s.newKey()
	if err != nil {
		return fmt.Errorf("failed to create recover key : %w", err)
	}

	updateKey, err := s.newKey()
	if err != nil {
		return fmt.Errorf("failed to update recover key : %w", err)
	}

	docResolution, err := s.vdr.Create(s.didMethod, didDoc,
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.AnchorOriginOpt, s.didAnchorOrigin),
	)
	if err != nil {
		return fmt.Errorf("failed to create DID : %w", err)
	}

	didID := docResolution.DIDDocument.ID

	err = resolveDID(s.vdr, didID, 10) //nolint:gomnd
	if err != nil {
		return fmt.Errorf("failed to resolve DID : %w", err)
	}

	request := &cshclientmodels.Profile{}
	request.Controller = &didID

	cshProfile, err := s.cshClient.PostHubstoreProfiles(
		operations.NewPostHubstoreProfilesParams().WithTimeout(requestTimeout).WithRequest(request))
	if err != nil {
		return err
	}

	// TODO need to find better way to get csh DID
	cshZCAP, err := zcapld.DecompressZCAP(cshProfile.Payload.Zcap)
	if err != nil {
		return fmt.Errorf("failed to parse CSH profile zcap: %w", err)
	}

	cshPubKeyURL, ok := cshZCAP.Proof[0]["verificationMethod"].(string)
	if !ok {
		return fmt.Errorf("failed to cast verificationMethod from cshZCAP")
	}

	config := &Config{
		DID:          didID,
		PubKeyID:     pubKeyID,
		PrivateKey:   privateKey,
		CSHPubKeyURL: cshPubKeyURL,
		CSHProfileID: cshProfile.Payload.ID,
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// store config
	return s.store.Put(configKeyDB, configBytes)
}

func (s *Service) newPublicKeys() (*docdid.Doc, string, ed25519.PrivateKey, error) {
	didDoc := &docdid.Doc{}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", nil, err
	}

	publicKeyID := uuid.New().String()

	jwk, err := jwksupport.JWKFromKey(publicKey)
	if err != nil {
		return nil, "", nil, err
	}

	vm, err := docdid.NewVerificationMethodFromJWK(publicKeyID, vccrypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, "", nil, err
	}

	didDoc.Authentication = append(didDoc.Authentication, *docdid.NewReferencedVerification(vm, docdid.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *docdid.NewReferencedVerification(vm, docdid.AssertionMethod))

	return didDoc, publicKeyID, privateKey, nil
}

func (s *Service) newKey() (crypto.PublicKey, error) {
	_, bits, err := s.keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
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

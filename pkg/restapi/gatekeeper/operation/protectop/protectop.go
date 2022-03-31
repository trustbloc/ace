/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protectop

//nolint: lll
//go:generate mockgen -destination gomocks_test.go -package protectop_test -source=protectop.go -mock_names vaultClient=MockVault,vdrRegistry=MockVDRIRegistry,storage=MockProtectedDataStore,vcProvider=MockVCProvider

import (
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

	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/model"
	"github.com/trustbloc/ace/pkg/restapi/vault"
	"github.com/trustbloc/ace/pkg/store/protecteddata"
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
	IssueCredential(credBytes []byte) (*verifiable.Credential, error)
}

// ProtectConfig defines external services used by protect ops.
type ProtectConfig struct {
	Store       storage
	VaultClient vaultClient
	VDRI        vdrRegistry
	VCIssuer    vcIssuer
}

// ProtectOperation implements protect operation.
type ProtectOperation struct {
	store       protecteddata.Storage
	vaultClient vaultClient
	vdri        vdrRegistry
	issuer      vcIssuer
}

// NewProtectOp creates new ProtectOperation.
func NewProtectOp(config *ProtectConfig) *ProtectOperation {
	return &ProtectOperation{
		store:       config.Store,
		vaultClient: config.VaultClient,
		vdri:        config.VDRI,
		issuer:      config.VCIssuer,
	}
}

// ProtectOp protect data and returns opaque did for it.
func (o *ProtectOperation) ProtectOp(req *models.ProtectReq) (*models.ProtectResp, error) {
	hash, err := calculateDataHash(req.Target)
	if err != nil {
		return nil, err
	}

	data, err := o.store.Get(hash)
	if err != nil {
		return nil, err
	}

	if data != nil {
		return &models.ProtectResp{Did: data.DID}, nil
	}

	vaultData, err := o.vaultClient.CreateVault()
	if err != nil {
		return nil, err
	}

	vaultID := vaultData.ID

	vc, err := o.wrapDataIntoVC(vaultID, req.Target)
	if err != nil {
		return nil, fmt.Errorf("wrap data into vc: %w", err)
	}

	// resolve DID
	err = resolveDID(o.vdri, vaultID, resolveMaxRetry)
	if err != nil {
		return nil, fmt.Errorf("resolve did %s : %w", vaultID, err)
	}

	targetVCDocID, err := o.saveVCDoc(vaultID, vc)
	if err != nil {
		return nil, fmt.Errorf("save vc doc: %w", err)
	}

	err = o.store.Put(&model.ProtectedData{
		PolicyID:      req.Policy,
		Hash:          hash,
		DID:           vaultID,
		TargetVCDocID: targetVCDocID,
	})

	if err != nil {
		return nil, fmt.Errorf("save sensitive data: %w", err)
	}

	return &models.ProtectResp{Did: vaultID}, nil
}

func (o *ProtectOperation) wrapDataIntoVC(sub, data string) (*verifiable.Credential, error) {
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

	vc, err := o.issuer.IssueCredential(credBytes)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *ProtectOperation) saveVCDoc(vaultID string, vc *verifiable.Credential) (string, error) {
	docID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return "", fmt.Errorf("create edv doc id : %w", err)
	}

	_, err = o.vaultClient.SaveDoc(vaultID, docID, vc)
	if err != nil {
		return "", fmt.Errorf("failed to save doc : %w", err)
	}

	return docID, nil
}

func calculateDataHash(data string) (string, error) {
	h := fnv.New128()

	if _, err := h.Write([]byte(data)); err != nil {
		return "", fmt.Errorf("calculate sensitive data hash fail: %w", err)
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

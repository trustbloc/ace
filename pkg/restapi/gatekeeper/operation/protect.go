/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/edv/pkg/edvutils"

	"github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/vcprovider"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/repository"
)

const (
	credentialContext = "https://www.w3.org/2018/credentials/v1"
)

// ProtectConfig defines external services used by protect ops.
type ProtectConfig struct {
	SensitiveDataRepository repository.ProtectedDataRepository
	VaultClient             vault.Vault
	VDRI                    vdrapi.Registry
	VCProvider              vcprovider.Provider
}

// ProtectOperation defines the interface for protect ops.
type ProtectOperation interface {
	ProtectOp(req *models.ProtectReq) (*models.ProtectResp, error)
}

// protectOperation implements protect operation.
type protectOperation struct {
	sensitiveDataRepository repository.ProtectedDataRepository
	vaultClient             vault.Vault
	vdri                    vdrapi.Registry
	vcProvider              vcprovider.Provider
}

// NewProtectOp creates new ProtectOperation.
func NewProtectOp(config *ProtectConfig) ProtectOperation {
	return &protectOperation{
		sensitiveDataRepository: config.SensitiveDataRepository,
		vaultClient:             config.VaultClient,
		vdri:                    config.VDRI,
		vcProvider:              config.VCProvider,
	}
}

func (o *protectOperation) ProtectOp(req *models.ProtectReq) (*models.ProtectResp, error) {
	hash, err := calculateDataHash(req.Target)
	if err != nil {
		return nil, err
	}

	data, err := o.sensitiveDataRepository.Get(hash)
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
	err = resolveDID(o.vdri, vaultID, 10)
	if err != nil {
		return nil, fmt.Errorf("resolve did %s : %w", vaultID, err)
	}

	targetVCDocID, err := o.saveVCDoc(vaultID, vc)
	if err != nil {
		return nil, fmt.Errorf("save vc doc: %w", err)
	}

	err = o.sensitiveDataRepository.Put(&repository.ProtectedData{
		Data:          req.Target,
		PolicyID:      req.Policy,
		Hash:          hash,
		DID:           vaultID,
		TargetVCDocID: targetVCDocID,
	})

	if err != nil {
		return nil, fmt.Errorf("save sensitive data: %w", err)
	}

	return &models.ProtectResp{Did: "did:example:12345"}, nil
}

func (o *protectOperation) wrapDataIntoVC(sub, data string) (*verifiable.Credential, error) {
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

	vc, err := o.vcProvider.IssueCredential(credBytes)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *protectOperation) saveVCDoc(vaultID string, vc *verifiable.Credential) (string, error) {
	docID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return "", fmt.Errorf("create edv doc id : %w", err)
	}

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("failed to save doc, marshal json failed : %w", err)
	}

	_, err = o.vaultClient.SaveDoc(vaultID, docID, bytes)
	if err != nil {
		return "", fmt.Errorf("failed to save doc : %w", err)
	}

	return docID, nil
}

func calculateDataHash(data string) (string, error) {
	h := fnv.New128()

	_, err := h.Write([]byte(data)) //nolint: ifshort
	if err != nil {
		return "", fmt.Errorf("calculate sensitive data hash fail: %w", err)
	}

	return string(h.Sum(nil)), nil
}

func resolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) error {
	for i := 1; i <= maxRetry; i++ {
		var err error
		_, err = vdrRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(1 * time.Second)

			continue
		}
	}

	return nil
}

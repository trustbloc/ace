/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"context"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	comparator "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	"github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/gatekeeper/collect"
	"github.com/trustbloc/ace/pkg/gatekeeper/extract"
	"github.com/trustbloc/ace/pkg/gatekeeper/policy"
	"github.com/trustbloc/ace/pkg/gatekeeper/protect"
	"github.com/trustbloc/ace/pkg/gatekeeper/release"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
	"github.com/trustbloc/ace/pkg/restapi/handler"
	"github.com/trustbloc/ace/pkg/restapi/mw/httpsigmw"
	"github.com/trustbloc/ace/pkg/vcissuer"
)

// Config defines configuration for Gatekeeper operations.
type Config struct {
	StorageProvider  storage.Provider
	VaultClient      vault.Vault
	ComparatorClient comparator.ClientService
	VDR              vdr.Registry
	VCIssuer         *vcissuer.Service
}

// New returns a new Controller instance.
func New(config *Config) (*Controller, error) {
	policyService, err := policy.NewService(config.StorageProvider)
	if err != nil {
		return nil, fmt.Errorf("create policy service: %w", err)
	}

	protectService, err := protect.NewService(&protect.Config{
		StoreProvider: config.StorageProvider,
		VaultClient:   config.VaultClient,
		VDR:           config.VDR,
		VCIssuer:      config.VCIssuer,
	})
	if err != nil {
		return nil, fmt.Errorf("create protect service: %w", err)
	}

	releaseService, err := release.NewService(&release.Config{
		StoreProvider:  config.StorageProvider,
		PolicyService:  policyService,
		ProtectService: protectService,
	})
	if err != nil {
		return nil, fmt.Errorf("create release service: %w", err)
	}

	collectService := collect.NewService(config.ComparatorClient, config.VaultClient)
	extractService := extract.NewService(config.ComparatorClient)

	op := &operation.Operation{
		PolicyService:   policyService,
		ProtectService:  protectService,
		ReleaseService:  releaseService,
		CollectService:  collectService,
		ExtractService:  extractService,
		SubjectResolver: &subjectDIDResolver{},
	}

	return &Controller{handlers: op.GetRESTHandlers()}, nil
}

type subjectDIDResolver struct{}

func (r *subjectDIDResolver) Resolve(ctx context.Context) (string, error) {
	sub, ok := httpsigmw.SubjectDID(ctx)
	if !ok {
		return "", fmt.Errorf("missing subject DID in context")
	}

	return sub, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []handler.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []handler.Handler {
	return c.handlers
}

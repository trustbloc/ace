/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/internal/common/support"
	"github.com/trustbloc/ace/pkg/protect"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
	"github.com/trustbloc/ace/pkg/store/policy"
	"github.com/trustbloc/ace/pkg/store/protecteddata"
	"github.com/trustbloc/ace/pkg/vcissuer"
)

// Config defines configuration for Gatekeeper operations.
type Config struct {
	StorageProvider storage.Provider
	VaultClient     vault.Vault
	VDR             vdrapi.Registry
	VCIssuer        *vcissuer.Service
}

// New returns new controller instance.
func New(config *Config) (*Controller, error) {
	protectedDataStore, err := protecteddata.New(config.StorageProvider)
	if err != nil {
		return nil, err
	}

	policyStore, err := policy.New(config.StorageProvider)
	if err != nil {
		return nil, err
	}

	protectSvc := protect.NewService(&protect.Config{
		Store:       protectedDataStore,
		VaultClient: config.VaultClient,
		VDR:         config.VDR,
		VCIssuer:    config.VCIssuer,
	})

	ops := &operation.Operation{
		ProtectSvc:  protectSvc,
		PolicyStore: policyStore,
	}

	return &Controller{handlers: ops.GetRESTHandlers()}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []support.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []support.Handler {
	return c.handlers
}

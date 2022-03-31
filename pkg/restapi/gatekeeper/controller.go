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
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper/operation/protectop"
	"github.com/trustbloc/ace/pkg/store/policy"
	"github.com/trustbloc/ace/pkg/store/protecteddata"
	"github.com/trustbloc/ace/pkg/vc"
)

// Config defines configuration for Gatekeeper operations.
type Config struct {
	StorageProvider storage.Provider
	VaultClient     vault.Vault
	VDRI            vdrapi.Registry
	VCIssuer        *vc.Issuer
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

	protectOp := protectop.NewProtectOp(&protectop.ProtectConfig{
		Store:       protectedDataStore,
		VaultClient: config.VaultClient,
		VDRI:        config.VDRI,
		VCIssuer:    config.VCIssuer,
	})

	ops := &operation.Operation{
		ProtectOperation: protectOp,
		PolicyStore:      policyStore,
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

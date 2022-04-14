/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"github.com/trustbloc/ace/pkg/restapi/comparator/operation"
	"github.com/trustbloc/ace/pkg/restapi/handler"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	comparatorService, err := operation.New(config)
	if err != nil {
		return nil, err
	}

	return &Controller{
		handlers: comparatorService.GetRESTHandlers(),
	}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []handler.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []handler.Handler {
	return c.handlers
}

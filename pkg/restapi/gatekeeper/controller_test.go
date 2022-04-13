/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper_test

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/gatekeeper"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := gatekeeper.New(&gatekeeper.Config{
			StorageProvider: storage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, controller)

		ops := controller.GetOperations()

		require.Greater(t, len(ops), 0)
	})
}

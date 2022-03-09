/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package healthcheck_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/restapi/healthcheck"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller := healthcheck.New()
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.Equal(t, 1, len(ops))
	})
}

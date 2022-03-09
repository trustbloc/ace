/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/ace/cmd/common"
)

const testLogModuleName = "test"

var logger = log.New(testLogModuleName)

func TestSetLogLevel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		resetLoggingLevels()

		common.SetDefaultLogLevel(logger, "debug")

		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level", func(t *testing.T) {
		resetLoggingLevels()

		common.SetDefaultLogLevel(logger, "mango")

		// Should remain unchanged
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func resetLoggingLevels() {
	log.SetLevel("", log.INFO)
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/ace/cmd/common"
)

func TestDBParams(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		expected := &common.DBParameters{
			URL:     "mem://test",
			Prefix:  "prefix",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		common.Flags(cmd)
		result, err := common.DBParams(cmd)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("use default timeout", func(t *testing.T) {
		expected := &common.DBParameters{
			URL:     "mem://test",
			Prefix:  "prefix",
			Timeout: common.DatabaseTimeoutDefault,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		err := os.Setenv(common.DatabaseTimeoutEnvKey, "")
		require.NoError(t, err)
		cmd := &cobra.Command{}
		common.Flags(cmd)
		result, err := common.DBParams(cmd)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error if url is missing", func(t *testing.T) {
		expected := &common.DBParameters{
			Prefix:  "prefix",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		common.Flags(cmd)
		_, err := common.DBParams(cmd)
		require.Error(t, err)
	})

	t.Run("error if prefix is missing", func(t *testing.T) {
		expected := &common.DBParameters{
			URL:     "mem://test",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		common.Flags(cmd)
		_, err := common.DBParams(cmd)
		require.Error(t, err)
	})

	t.Run("error if timeout has an invalid value", func(t *testing.T) {
		expected := &common.DBParameters{
			URL:    "mem://test",
			Prefix: "prefix",
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		err := os.Setenv(common.DatabaseTimeoutEnvKey, "invalid")
		require.NoError(t, err)
		cmd := &cobra.Command{}
		common.Flags(cmd)
		_, err = common.DBParams(cmd)
		require.Error(t, err)
	})
}

func TestInitStore(t *testing.T) {
	t.Run("store", func(t *testing.T) {
		t.Run("inits ok", func(t *testing.T) {
			t.Run("mem", func(t *testing.T) {
				s, err := common.InitStore(&common.DBParameters{
					URL:     "mem://test",
					Prefix:  "test",
					Timeout: 30,
				}, log.New("test"))
				require.NoError(t, err)
				require.NotNil(t, s)
			})
			t.Run("MongoDB", func(t *testing.T) {
				s, err := common.InitStore(&common.DBParameters{
					URL:     "mongodb://test",
					Prefix:  "test",
					Timeout: 30,
				}, log.New("test"))
				require.NoError(t, err)
				require.NotNil(t, s)
			})
		})

		t.Run("error if url format is invalid", func(t *testing.T) {
			_, err := common.InitStore(&common.DBParameters{
				URL:     "invalid",
				Prefix:  "test",
				Timeout: 30,
			}, log.New("test"))
			require.Error(t, err)
		})

		t.Run("error if driver is not supported", func(t *testing.T) {
			_, err := common.InitStore(&common.DBParameters{
				URL:     "unsupported://test",
				Prefix:  "test",
				Timeout: 30,
			}, log.New("test"))
			require.Error(t, err)
		})

		t.Run("error if cannot connect to store", func(t *testing.T) {
			invalid := []string{
				"mysql://test:secret@tcp(localhost:5984)",
				"couchdb://test:secret@localhost:5984",
			}

			for _, url := range invalid {
				_, err := common.InitStore(&common.DBParameters{
					URL:     url,
					Prefix:  "test",
					Timeout: 1,
				}, log.New("test"))
				require.Error(t, err)
			}
		})
	})
}

func setEnv(t *testing.T, values *common.DBParameters) {
	t.Helper()

	err := os.Setenv(common.DatabaseURLEnvKey, values.URL)
	require.NoError(t, err)

	err = os.Setenv(common.DatabasePrefixEnvKey, values.Prefix)
	require.NoError(t, err)

	err = os.Setenv(common.DatabaseTimeoutEnvKey, strconv.FormatUint(values.Timeout, 10))
	require.NoError(t, err)
}

func unsetEnv(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(common.DatabaseURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(common.DatabasePrefixEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(common.DatabaseTimeoutEnvKey)
	require.NoError(t, err)
}

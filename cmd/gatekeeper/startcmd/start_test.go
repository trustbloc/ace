/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd //nolint:testpackage

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/cmd/common"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certPath, keyPath string, handler http.Handler) error {
	return nil
}

func TestListenAndServe(t *testing.T) {
	var w HTTPServer
	err := w.ListenAndServe("wronghost", "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "address wronghost: missing port in address")
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor GK_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing db url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"failed to configure dbURL: Neither database-url (command line flag)"+
				" nor DATABASE_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing dbPrefix arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + common.DatabaseURLFlagName, "mem://test",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"failed to configure dbPrefix: Neither database-prefix (command line flag)"+
				" nor DATABASE_PREFIX (environment variable) have been set.",
			err.Error())
	})
}

func TestNotSupportedDSN(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + common.DatabaseURLFlagName, "mem1://test",
		"--" + common.DatabasePrefixFlagName, "test_",
		"--" + didResolverURLFlagName, "https://did-resolver-url",
		"--" + vaultServerURLFlagName, "https://vault-server-url",
		"--" + vcIssuerURLFlagName, "https://vc-isssuer-url",
		"--" + didAnchorOriginFlagName, "https://did-anchor-orign",
		"--" + cshURLFlagName, "https://csh-url",
		"--" + vcIssuerProfileFlagName, "test-profile",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported storage driver: mem1")
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "GK_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + common.DatabaseURLFlagName, "mem://test",
		"--" + common.DatabasePrefixFlagName, "test_",
		"--" + didResolverURLFlagName, "https://did-resolver-url",
		"--" + vaultServerURLFlagName, "https://vault-server-url",
		"--" + vcIssuerURLFlagName, "https://vc-isssuer-url",
		"--" + didAnchorOriginFlagName, "https://did-anchor-orign",
		"--" + cshURLFlagName, "https://csh-url",
		"--" + vcIssuerProfileFlagName, "test-profile",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(), "failed to create DID")
}

func TestTLSInvalidArgs(t *testing.T) {
	t.Run("test wrong tls cert pool flag", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + tlsSystemCertPoolFlagName, "wrong",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
	})
}

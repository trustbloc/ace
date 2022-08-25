/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main Gatekeeper REST API.
//
// Gatekeeper helps to ensure that there are multiple authorizations for accessing protected data under
// the given policy.
//
//     Schemes: http, https
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/spf13/cobra"

	"github.com/trustbloc/ace/cmd/gatekeeper/startcmd"
)

var logger = log.New("gatekeeper-rest")

func main() {
	rootCmd := &cobra.Command{
		Use: "gatekeeper-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("execute root cmd: %s", err.Error())
	}
}

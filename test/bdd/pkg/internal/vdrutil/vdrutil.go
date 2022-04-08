/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"fmt"
	"strings"
	"time"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// ResolveDID waits for the DID to become available for resolution.
func ResolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var docResolution *docdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = vdrRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(3 * time.Second) //nolint:gomnd

			continue
		}

		// check v1 DID is register
		// v1 will return DID with placeholder keys ID (DID#DID) when not register
		// will not return 404
		if strings.Contains(docResolution.DIDDocument.ID, "did:v1") {
			split := strings.Split(docResolution.DIDDocument.AssertionMethod[0].VerificationMethod.ID, "#")
			if strings.Contains(docResolution.DIDDocument.ID, split[1]) {
				fmt.Printf("v1 did %s not register yet will retry %d of %d\n", did, i, maxRetry)
				time.Sleep(3 * time.Second) //nolint:gomnd

				continue
			}
		}
	}

	return docResolution.DIDDocument, nil
}

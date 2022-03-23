/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/trustbloc/ace/pkg/restapi/model"

// createPolicyReq model
//
// swagger:parameters createPolicyReq
type createPolicyReq struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		model.PolicyDocument
	}
}

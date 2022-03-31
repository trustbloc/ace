/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcissuer_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/cmd/common"
	"github.com/trustbloc/ace/pkg/vcissuer"
)

//nolint:lll
const vcContent = `
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc-revocation-list-2020/v1"
   ],
   "credentialStatus":{
      "id":"http://vc-issuer.trustbloc.local:8070/vc-issuer-gk/status/1#0",
      "revocationListCredential":"http://vc-issuer.trustbloc.local:8070/vc-issuer-gk/status/1",
      "revocationListIndex":"0",
      "type":"RevocationList2020Status"
   },
   "credentialSubject":{
      "data":"@thanos27",
      "id":"did:orb:EiDrvGeIdkhnpkFI0ORiGuUj1DapwBCszUCEOFMb2-_Vaw"
   },
   "id":"urn:uuid:4d1f25ab-cf2f-498f-b9bd-d38ce5e426a1",
   "issuanceDate":"2022-03-30T14:16:36.547716722Z",
   "issuer":"urn:uuid:4249a22a-7c06-4ff4-8835-7c1ab62a2ce5",
   "proof":{
      "created":"2022-03-30T14:16:36.571511392Z",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..9Z_NRlxuFZIKGYb8C4Xl53h_BJAb9rfrAojAbWqBFKz347USmNkHoBkdqv9IHuIXuaiECYII3d_mA4n6VUFSBw",
      "proofPurpose":"assertionMethod",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:orb:EiDlO1W_fQvFX0lB1HBxp3Om-JIjXvWFCXaLzeKQWs611A#0a2418dc-2a35-4bbf-a5b2-08ab3702025d"
   },
   "type":"VerifiableCredential"
}
`

func TestIssueCredential_HTTPFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	httpClient := NewMockHTTPClient(ctrl)

	httpClient.EXPECT().Do(gomock.Any()).Return(nil, errors.New("request failed"))

	vcIssuer := vcissuer.New(&vcissuer.Config{
		VCIssuerURL: "",
		HTTPClient:  httpClient,
	})

	_, err := vcIssuer.IssueCredential(context.Background(), []byte{})
	require.Contains(t, err.Error(), "request failed")
}

func TestIssueCredential_VCParseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	httpClient := NewMockHTTPClient(ctrl)

	httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		Body:       io.NopCloser(strings.NewReader("Invalid VC")),
		StatusCode: http.StatusCreated,
	}, nil)

	vcIssuer := vcissuer.New(&vcissuer.Config{
		VCIssuerURL:    "http://base-url",
		AuthToken:      "auth-token",
		DocumentLoader: nil,
		HTTPClient:     httpClient,
	})

	_, err := vcIssuer.IssueCredential(context.Background(), []byte{})
	require.Contains(t, err.Error(), "parse vc: unmarshal new credential")
}

func TestIssueCredential_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	httpClient := NewMockHTTPClient(ctrl)

	httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
		require.Equal(t, req.URL.Host, "base-url")

		authTokens := req.Header["Authorization"]
		require.Equal(t, 1, len(authTokens))
		require.Equal(t, authTokens[0], "Bearer auth-token")
	}).Return(&http.Response{
		Body:       io.NopCloser(strings.NewReader(vcContent)),
		StatusCode: http.StatusCreated,
	}, nil)

	ldStore, err := common.CreateLDStoreProvider(mem.NewProvider())
	require.NoError(t, err)

	documentLoader, err := common.CreateJSONLDDocumentLoader(ldStore, httpClient, nil)
	require.NoError(t, err)

	vcIssuer := vcissuer.New(&vcissuer.Config{
		VCIssuerURL:    "http://base-url",
		AuthToken:      "auth-token",
		DocumentLoader: documentLoader,
		HTTPClient:     httpClient,
	})

	cred, err := vcIssuer.IssueCredential(context.Background(), []byte{})
	require.NoError(t, err)
	require.NotNil(t, cred)
}

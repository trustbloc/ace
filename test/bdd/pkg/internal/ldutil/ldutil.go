/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldutil

import (
	_ "embed" // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// Embedded test contexts.
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/governance.jsonld
	governanceVocab []byte
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocab []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
)

var extraContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
		Content: governanceVocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     citizenshipVocab,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: examplesVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		Content: examplesExtVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-crude-product-v1.jsonld",
		Content: examplesCrudeProductVocab,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// DocumentLoader returns a JSON-LD document loader with preloaded test contexts.
func DocumentLoader() (*ld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := ld.NewDocumentLoader(ldStore, ld.WithExtraContexts(extraContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}

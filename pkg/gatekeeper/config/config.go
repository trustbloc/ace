/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package config

import "crypto/ed25519"

// Config contains configuration of Gatekeeper identity and csh profile.
type Config struct {
	// The gatekeeper's unique DID.
	DID string `json:"did"`

	// The gatekeeper's DID public key.
	PubKeyID string `json:"pubKeyID"`

	// The gatekeeper's DID private key.
	PrivateKey ed25519.PrivateKey `json:"privateKey"`

	// The CSH public key's keyID in the format of a DID URL.
	CSHPubKeyURL string `json:"cshPubKeyURL"`

	// The CSH profile created by gatekeeper.
	CSHProfileID string `json:"cshProfileID"`
}

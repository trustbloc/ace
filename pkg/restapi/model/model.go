/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// UNIRegistrar uni-registrar.
type UNIRegistrar struct {
	DriverURL string            `json:"driverURL,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// ErrorResponse to send error message in the response.
type ErrorResponse struct {
	// error message
	Message string `json:"errMessage,omitempty"`
}

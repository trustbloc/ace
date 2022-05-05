/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package extract_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	"github.com/trustbloc/ace/pkg/client/csh/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/extract"
)

func TestExtract_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cshClient := NewMockCSHClient(ctrl)

	cshClient.EXPECT().PostExtract(gomock.Any()).Return(
		&operations.PostExtractOK{
			Payload: models.ExtractionResponse{
				&models.ExtractionResponseItems0{
					Document: "target",
				},
			},
		}, nil)

	srv := extract.NewService(cshClient)

	target, err := srv.Extract(context.Background(), "queryId")

	require.NoError(t, err)
	require.Equal(t, "target", target)
}

func TestExtract_PostExtract_Fail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cshClient := NewMockCSHClient(ctrl)
	cshClient.EXPECT().PostExtract(gomock.Any()).Return(nil, errors.New("post extract failed"))

	srv := extract.NewService(cshClient)

	_, err := srv.Extract(context.Background(), "auth-token")

	require.Contains(t, err.Error(), "post extract failed")
}

func TestExtract_InvalidResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cshClient := NewMockCSHClient(ctrl)
	cshClient.EXPECT().PostExtract(gomock.Any()).Return(
		&operations.PostExtractOK{
			Payload: models.ExtractionResponse{
				{
					Document: "target",
				},
				{
					Document: "target",
				},
			},
		}, nil)

	srv := extract.NewService(cshClient)

	_, err := srv.Extract(context.Background(), "auth-token")
	require.Error(t, err)
}

func TestExtract_InvalidType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cshClient := NewMockCSHClient(ctrl)
	cshClient.EXPECT().PostExtract(gomock.Any()).Return(
		&operations.PostExtractOK{
			Payload: models.ExtractionResponse{
				{
					Document: 10,
				},
			},
		}, nil)

	srv := extract.NewService(cshClient)

	_, err := srv.Extract(context.Background(), "auth-token")
	require.Error(t, err)
}

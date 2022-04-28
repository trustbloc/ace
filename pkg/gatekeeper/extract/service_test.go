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

	compclientops "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	"github.com/trustbloc/ace/pkg/client/comparator/models"
	"github.com/trustbloc/ace/pkg/gatekeeper/extract"
)

func TestExtract_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	comparator.EXPECT().PostExtract(gomock.Any()).Return(&compclientops.PostExtractOK{
		Payload: &models.ExtractResp{
			Documents: []*models.ExtractRespDocumentsItems0{{
				Contents: "target",
			}},
		},
	}, nil)

	srv := extract.NewService(comparator)

	target, err := srv.Extract(context.Background(), "auth-token")

	require.NoError(t, err)
	require.Equal(t, "target", target)
}

func TestExtract_PostExtract_Fail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	comparator.EXPECT().PostExtract(gomock.Any()).Return(nil, errors.New("post extract failed"))

	srv := extract.NewService(comparator)

	_, err := srv.Extract(context.Background(), "auth-token")

	require.Contains(t, err.Error(), "post extract failed")
}

func TestExtract_InvalidResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	comparator.EXPECT().PostExtract(gomock.Any()).Return(&compclientops.PostExtractOK{
		Payload: &models.ExtractResp{
			Documents: []*models.ExtractRespDocumentsItems0{
				{
					Contents: "target",
				},
				{
					Contents: "target",
				},
			},
		},
	}, nil)

	srv := extract.NewService(comparator)

	_, err := srv.Extract(context.Background(), "auth-token")
	require.Error(t, err)
}

func TestExtract_InvalidType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	comparator := NewMockComparator(ctrl)
	comparator.EXPECT().PostExtract(gomock.Any()).Return(&compclientops.PostExtractOK{
		Payload: &models.ExtractResp{
			Documents: []*models.ExtractRespDocumentsItems0{
				{
					Contents: 10,
				},
			},
		},
	}, nil)

	srv := extract.NewService(comparator)

	_, err := srv.Extract(context.Background(), "auth-token")
	require.Error(t, err)
}

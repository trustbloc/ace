/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package extract

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package extract_test -source=service.go -mock_names cshClient=MockCSHClient

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/trustbloc/ace/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/ace/pkg/client/csh/models"
)

const (
	requestTimeout = 30 * time.Second
)

type cshClient interface {
	PostExtract(params *operations.PostExtractParams,
		opts ...operations.ClientOption) (*operations.PostExtractOK, error)
}

// Service is a service for extracting protected resources.
type Service struct {
	cshClient cshClient
}

// NewService returns extract service.
func NewService(cshClient cshClient) *Service {
	return &Service{
		cshClient: cshClient,
	}
}

// Extract extracts protected data from access handle.
func (s *Service) Extract(_ context.Context, queryID string) (string, error) {
	refQuery := &cshclientmodels.RefQuery{Ref: &queryID}
	refQuery.SetID(uuid.NewString())

	extractions, err := s.cshClient.PostExtract(
		operations.NewPostExtractParams().
			WithTimeout(requestTimeout).
			WithRequest([]cshclientmodels.Query{refQuery}),
	)
	if err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}

	if len(extractions.Payload) != 1 {
		return "", fmt.Errorf("extract: invalid extract response len")
	}

	content, ok := extractions.Payload[0].Document.(string)
	if !ok {
		return "", fmt.Errorf("extract: invalid content type, should be string")
	}

	return content, nil
}

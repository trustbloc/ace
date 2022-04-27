/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package extract

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -package extract_test -source=service.go -mock_names comparatorClient=MockComparator

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	compclientops "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodel "github.com/trustbloc/ace/pkg/client/comparator/models"
)

const (
	requestTimeout = 30 * time.Second
)

type comparatorClient interface {
	PostExtract(params *compclientops.PostExtractParams) (*compclientops.PostExtractOK, error)
}

// Service is a service for extracting protected resources.
type Service struct {
	compClient comparatorClient
}

// NewService returns extract service.
func NewService(compClient comparatorClient) *Service {
	return &Service{
		compClient: compClient,
	}
}

// Extract extracts protected data from access handle.
func (s *Service) Extract(_ context.Context, authToken string) (string, error) {
	query := &compmodel.AuthorizedQuery{AuthToken: &authToken}
	query.SetID(uuid.NewString())

	request := &compmodel.Extract{}
	request.SetQueries([]compmodel.Query{
		query,
	})

	extractRes, err := s.compClient.PostExtract(
		compclientops.NewPostExtractParams().WithTimeout(requestTimeout).WithExtract(request),
	)
	if err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}

	if len(extractRes.Payload.Documents) != 1 {
		return "", fmt.Errorf("extract: invalid extract response len")
	}

	content, ok := extractRes.Payload.Documents[0].Contents.(string)
	if !ok {
		return "", fmt.Errorf("extract: invalid content type, should be string")
	}

	return content, nil
}

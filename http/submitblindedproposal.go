// Copyright © 2023, 2024 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	client "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-builder-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SubmitBlindedProposalV2 submits a blinded proposal.
func (s *Service) SubmitBlindedProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "SubmitBlindedProposalV2", trace.WithAttributes(
		attribute.String("relay", s.Address()),
	))
	defer span.End()

	if opts == nil {
		return client.ErrNoOptions
	}

	if opts.Proposal == nil {
		return errors.Join(errors.New("no proposal specified"), client.ErrInvalidOptions)
	}

	switch opts.Proposal.Version {
	case consensusspec.DataVersionBellatrix:
		if opts.Proposal.Bellatrix == nil {
			return errors.New("bellatrix proposal without payload")
		}

		return s.submitBellatrixProposalV2(ctx, opts)
	case consensusspec.DataVersionCapella:
		if opts.Proposal.Capella == nil {
			return errors.New("capella proposal without payload")
		}

		return s.submitCapellaProposalV2(ctx, opts)
	case consensusspec.DataVersionDeneb:
		if opts.Proposal.Deneb == nil {
			return errors.New("deneb proposal without payload")
		}

		return s.submitDenebProposalV2(ctx, opts)
	case consensusspec.DataVersionElectra:
		if opts.Proposal.Electra == nil {
			return errors.New("electra proposal without payload")
		}

		return s.submitElectraProposalV2(ctx, opts)
	case consensusspec.DataVersionFulu:
		if opts.Proposal.Fulu == nil {
			return errors.New("fulu proposal without payload")
		}

		return s.submitFuluProposalV2(ctx, opts)
	default:
		return fmt.Errorf("unhandled data version %v", opts.Proposal.Version)
	}
}

func (s *Service) submitBellatrixProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	proposal := opts.Proposal.Bellatrix

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	// Submit the blinded proposal.
	// Returns 202 if the proposal is valid.
	// Returns 400 if the proposal is invalid.
	httpResponse, err := s.post(ctx,
		"/eth/v2/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	switch httpResponse.statusCode {
	case http.StatusAccepted:
		return nil
	default:
		return fmt.Errorf("unexpected status code %v", httpResponse.statusCode)
	}
}

func (s *Service) submitCapellaProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	proposal := opts.Proposal.Capella

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	// Submit the blinded proposal.
	// Returns 202 if the proposal is valid.
	// Returns 400 if the proposal is invalid.
	httpResponse, err := s.post(ctx,
		"/eth/v2/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	switch httpResponse.statusCode {
	case http.StatusAccepted:
		return nil
	default:
		return fmt.Errorf("unexpected status code %v", httpResponse.statusCode)
	}
}

func (s *Service) submitDenebProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	proposal := opts.Proposal.Deneb

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	// Submit the blinded proposal.
	// Returns 202 if the proposal is valid.
	// Returns 400 if the proposal is invalid.
	httpResponse, err := s.post(ctx,
		"/eth/v2/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	switch httpResponse.statusCode {
	case http.StatusAccepted:
		return nil
	default:
		return fmt.Errorf("unexpected status code %v", httpResponse.statusCode)
	}
}

func (s *Service) submitElectraProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	proposal := opts.Proposal.Electra

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	// Submit the blinded proposal.
	// Returns 202 if the proposal is valid.
	// Returns 400 if the proposal is invalid.
	httpResponse, err := s.post(ctx,
		"/eth/v2/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	switch httpResponse.statusCode {
	case http.StatusAccepted:
		return nil
	default:
		return fmt.Errorf("unexpected status code %v", httpResponse.statusCode)
	}
}

func (s *Service) submitFuluProposalV2(ctx context.Context,
	opts *api.SubmitBlindedProposalOpts,
) error {
	proposal := opts.Proposal.Fulu

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	// Submit the blinded proposal.
	// Returns 202 if the proposal is valid.
	// Returns 400 if the proposal is invalid.
	httpResponse, err := s.post(ctx,
		"/eth/v2/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	switch httpResponse.statusCode {
	case http.StatusAccepted:
		return nil
	default:
		return fmt.Errorf("unexpected status code %v", httpResponse.statusCode)
	}
}

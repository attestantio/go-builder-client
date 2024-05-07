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
	"fmt"
	"time"

	apideneb "github.com/attestantio/go-builder-client/api/deneb"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	consensusapiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	consensusapiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusapiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// UnblindProposal unblinds a proposal.
func (s *Service) UnblindProposal(ctx context.Context,
	proposal *consensusapi.VersionedSignedBlindedProposal,
) (
	*consensusapi.VersionedSignedProposal,
	error,
) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "UnblindProposal", trace.WithAttributes(
		attribute.String("relay", s.Address()),
	))
	defer span.End()
	started := time.Now()

	if proposal == nil {
		return nil, errors.New("no proposal supplied")
	}

	switch proposal.Version {
	case consensusspec.DataVersionBellatrix:
		if proposal.Bellatrix == nil {
			return nil, errors.New("bellatrix proposal without payload")
		}

		return s.unblindBellatrixProposal(ctx, started, proposal.Bellatrix)
	case consensusspec.DataVersionCapella:
		if proposal.Capella == nil {
			return nil, errors.New("capella proposal without payload")
		}

		return s.unblindCapellaProposal(ctx, started, proposal.Capella)
	case consensusspec.DataVersionDeneb:
		if proposal.Deneb == nil {
			return nil, errors.New("deneb proposal without payload")
		}

		return s.unblindDenebProposal(ctx, started, proposal.Deneb)
	default:
		return nil, fmt.Errorf("unhandled data version %v", proposal.Version)
	}
}

func (s *Service) unblindBellatrixProposal(ctx context.Context,
	started time.Time,
	proposal *consensusapiv1bellatrix.SignedBlindedBeaconBlock,
) (
	*consensusapi.VersionedSignedProposal,
	error,
) {
	specJSON, err := json.Marshal(proposal)
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to marshal JSON")
	}

	httpResponse, err := s.post(ctx, "/eth/v1/builder/blinded_blocks", "", bytes.NewBuffer(specJSON), ContentTypeJSON, map[string]string{})
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to submit unblind proposal request")
	}

	res := &consensusapi.VersionedSignedProposal{
		Version: consensusspec.DataVersionBellatrix,
		Bellatrix: &bellatrix.SignedBeaconBlock{
			Message: &bellatrix.BeaconBlock{
				Slot:          proposal.Message.Slot,
				ProposerIndex: proposal.Message.ProposerIndex,
				ParentRoot:    proposal.Message.ParentRoot,
				StateRoot:     proposal.Message.StateRoot,
				Body: &bellatrix.BeaconBlockBody{
					RANDAOReveal:      proposal.Message.Body.RANDAOReveal,
					ETH1Data:          proposal.Message.Body.ETH1Data,
					Graffiti:          proposal.Message.Body.Graffiti,
					ProposerSlashings: proposal.Message.Body.ProposerSlashings,
					AttesterSlashings: proposal.Message.Body.AttesterSlashings,
					Attestations:      proposal.Message.Body.Attestations,
					Deposits:          proposal.Message.Body.Deposits,
					VoluntaryExits:    proposal.Message.Body.VoluntaryExits,
					SyncAggregate:     proposal.Message.Body.SyncAggregate,
				},
			},
			Signature: proposal.Signature,
		},
	}

	switch httpResponse.contentType {
	case ContentTypeJSON:
		res.Bellatrix.Message.Body.ExecutionPayload, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), &bellatrix.ExecutionPayload{})
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse bellatrix response")
		}
		// Ensure that the data returned is what we expect.
		ourExecutionPayloadHash, err := proposal.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for our execution payload header")
		}
		receivedExecutionPayloadHash, err := res.Bellatrix.Message.Body.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for the received execution payload")
		}
		if !bytes.Equal(ourExecutionPayloadHash[:], receivedExecutionPayloadHash[:]) {
			return nil, fmt.Errorf("execution payload hash mismatch: %#x != %#x", receivedExecutionPayloadHash[:], ourExecutionPayloadHash[:])
		}
	default:
		return nil, fmt.Errorf("unsupported content type %v", httpResponse.contentType)
	}
	monitorOperation(s.Address(), "unblind proposal", "succeeded", time.Since(started))

	return res, nil
}

func (s *Service) unblindCapellaProposal(ctx context.Context,
	started time.Time,
	proposal *consensusapiv1capella.SignedBlindedBeaconBlock,
) (
	*consensusapi.VersionedSignedProposal,
	error,
) {
	specJSON, err := json.Marshal(proposal)
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to marshal JSON")
	}

	httpResponse, err := s.post(ctx, "/eth/v1/builder/blinded_blocks", "", bytes.NewBuffer(specJSON), ContentTypeJSON, map[string]string{})
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to submit unblind proposal request")
	}

	res := &consensusapi.VersionedSignedProposal{
		Version: consensusspec.DataVersionCapella,
		Capella: &capella.SignedBeaconBlock{
			Message: &capella.BeaconBlock{
				Slot:          proposal.Message.Slot,
				ProposerIndex: proposal.Message.ProposerIndex,
				ParentRoot:    proposal.Message.ParentRoot,
				StateRoot:     proposal.Message.StateRoot,
				Body: &capella.BeaconBlockBody{
					RANDAOReveal:          proposal.Message.Body.RANDAOReveal,
					ETH1Data:              proposal.Message.Body.ETH1Data,
					Graffiti:              proposal.Message.Body.Graffiti,
					ProposerSlashings:     proposal.Message.Body.ProposerSlashings,
					AttesterSlashings:     proposal.Message.Body.AttesterSlashings,
					Attestations:          proposal.Message.Body.Attestations,
					Deposits:              proposal.Message.Body.Deposits,
					VoluntaryExits:        proposal.Message.Body.VoluntaryExits,
					SyncAggregate:         proposal.Message.Body.SyncAggregate,
					BLSToExecutionChanges: proposal.Message.Body.BLSToExecutionChanges,
				},
			},
			Signature: proposal.Signature,
		},
	}

	switch httpResponse.contentType {
	case ContentTypeJSON:
		res.Capella.Message.Body.ExecutionPayload, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), &capella.ExecutionPayload{})
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse capella response")
		}
		// Ensure that the data returned is what we expect.
		ourExecutionPayloadHash, err := proposal.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for our execution payload header")
		}
		receivedExecutionPayloadHash, err := res.Capella.Message.Body.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for the received execution payload")
		}
		if !bytes.Equal(ourExecutionPayloadHash[:], receivedExecutionPayloadHash[:]) {
			return nil, fmt.Errorf("execution payload hash mismatch: %#x != %#x", receivedExecutionPayloadHash[:], ourExecutionPayloadHash[:])
		}
	default:
		return nil, fmt.Errorf("unsupported content type %v", httpResponse.contentType)
	}
	monitorOperation(s.Address(), "unblind proposal", "succeeded", time.Since(started))

	return res, nil
}

func (s *Service) unblindDenebProposal(ctx context.Context,
	started time.Time,
	proposal *consensusapiv1deneb.SignedBlindedBeaconBlock,
) (
	*consensusapi.VersionedSignedProposal,
	error,
) {
	specJSON, err := json.Marshal(proposal)
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to marshal JSON")
	}

	httpResponse, err := s.post(ctx, "/eth/v1/builder/blinded_blocks", "", bytes.NewBuffer(specJSON), ContentTypeJSON, map[string]string{})
	if err != nil {
		monitorOperation(s.Address(), "unblind proposal", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to submit unblind proposal request")
	}

	// Reconstruct proposal.
	res := &consensusapi.VersionedSignedProposal{
		Version: consensusspec.DataVersionDeneb,
		Deneb: &consensusapiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message: &deneb.BeaconBlock{
					Slot:          proposal.Message.Slot,
					ProposerIndex: proposal.Message.ProposerIndex,
					ParentRoot:    proposal.Message.ParentRoot,
					StateRoot:     proposal.Message.StateRoot,
					Body: &deneb.BeaconBlockBody{
						RANDAOReveal:          proposal.Message.Body.RANDAOReveal,
						ETH1Data:              proposal.Message.Body.ETH1Data,
						Graffiti:              proposal.Message.Body.Graffiti,
						ProposerSlashings:     proposal.Message.Body.ProposerSlashings,
						AttesterSlashings:     proposal.Message.Body.AttesterSlashings,
						Attestations:          proposal.Message.Body.Attestations,
						Deposits:              proposal.Message.Body.Deposits,
						VoluntaryExits:        proposal.Message.Body.VoluntaryExits,
						SyncAggregate:         proposal.Message.Body.SyncAggregate,
						BLSToExecutionChanges: proposal.Message.Body.BLSToExecutionChanges,
						BlobKZGCommitments:    proposal.Message.Body.BlobKZGCommitments,
					},
				},
				Signature: proposal.Signature,
			},
		},
	}

	switch httpResponse.contentType {
	case ContentTypeJSON:
		bundle, _, err := decodeJSONResponse(bytes.NewReader(httpResponse.body), &apideneb.ExecutionPayloadAndBlobsBundle{})
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse deneb response")
		}
		// Ensure that the data returned is what we expect.
		ourExecutionPayloadHash, err := proposal.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for our execution payload header")
		}
		receivedExecutionPayloadHash, err := bundle.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate hash tree root for the received execution payload")
		}
		if !bytes.Equal(ourExecutionPayloadHash[:], receivedExecutionPayloadHash[:]) {
			return nil, fmt.Errorf("execution payload hash mismatch: %#x != %#x", receivedExecutionPayloadHash[:], ourExecutionPayloadHash[:])
		}
		res.Deneb.SignedBlock.Message.Body.ExecutionPayload = bundle.ExecutionPayload

		// Reconstruct blobs.
		res.Deneb.KZGProofs = make([]deneb.KZGProof, len(bundle.BlobsBundle.Proofs))
		res.Deneb.Blobs = make([]deneb.Blob, len(bundle.BlobsBundle.Blobs))
		for i := range bundle.BlobsBundle.Blobs {
			if !bytes.Equal(bundle.BlobsBundle.Commitments[i][:], res.Deneb.SignedBlock.Message.Body.BlobKZGCommitments[i][:]) {
				return nil, fmt.Errorf("blob %d commitment mismatch", i)
			}

			res.Deneb.KZGProofs[i] = bundle.BlobsBundle.Proofs[i]
			res.Deneb.Blobs[i] = bundle.BlobsBundle.Blobs[i]
		}
	default:
		return nil, fmt.Errorf("unsupported content type %v", httpResponse.contentType)
	}
	monitorOperation(s.Address(), "unblind proposal", "succeeded", time.Since(started))

	return res, nil
}

// Copyright © 2025 Attestant Limited.
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
	"strings"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/fulu"
	"github.com/attestantio/go-builder-client/spec"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	consensusapiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
)

func (s *Service) unblindFuluProposal(ctx context.Context,
	opts *api.UnblindProposalOpts,
) (
	*api.Response[*consensusapi.VersionedSignedProposal],
	error,
) {
	proposal := opts.Proposal.Fulu

	specJSON, err := json.Marshal(proposal)
	if err != nil {
		return nil, errors.Join(errors.New("failed to marshal JSON"), err)
	}

	headers := make(map[string]string)
	headers["Eth-Consensus-Version"] = strings.ToLower(opts.Proposal.Version.String())

	httpResponse, err := s.post(ctx,
		"/eth/v1/builder/blinded_blocks",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		headers,
		true,
	)
	if err != nil {
		return nil, errors.Join(errors.New("failed to submit unblind proposal request"), err)
	}

	// Reconstruct proposal.
	res := &consensusapi.VersionedSignedProposal{
		Version: consensusspec.DataVersionFulu,
		Fulu: &consensusapiv1electra.SignedBlockContents{
			SignedBlock: &electra.SignedBeaconBlock{
				Message: &electra.BeaconBlock{
					Slot:          proposal.Message.Slot,
					ProposerIndex: proposal.Message.ProposerIndex,
					ParentRoot:    proposal.Message.ParentRoot,
					StateRoot:     proposal.Message.StateRoot,
					Body: &electra.BeaconBlockBody{
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
						ExecutionRequests:     proposal.Message.Body.ExecutionRequests,
					},
				},
				Signature: proposal.Signature,
			},
		},
	}

	// Populate from response.
	switch httpResponse.contentType {
	case ContentTypeJSON:
		bundle := &fulu.ExecutionPayloadAndBlobsBundle{}
		_, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), bundle)
		if err != nil {
			return nil, errors.Join(errors.New("failed to decode fulu execution payload and blobs bundle"), err)
		}
		res.Fulu.SignedBlock.Message.Body.ExecutionPayload = bundle.ExecutionPayload
		res.Fulu.Blobs = make([]deneb.Blob, len(bundle.BlobsBundle.Blobs))
		for i := range bundle.BlobsBundle.Blobs {
			res.Fulu.Blobs[i] = bundle.BlobsBundle.Blobs[i]
		}
		res.Fulu.KZGProofs = make([]deneb.KZGProof, len(bundle.BlobsBundle.Proofs))
		for i := range bundle.BlobsBundle.Proofs {
			res.Fulu.KZGProofs[i] = bundle.BlobsBundle.Proofs[i]
		}
	case ContentTypeSSZ:
		bundle := &spec.VersionedSubmitBlockRequest{
			Version: consensusspec.DataVersionFulu,
			Fulu:    &fulu.SubmitBlockRequest{},
		}
		if err := bundle.Fulu.UnmarshalSSZ(httpResponse.body); err != nil {
			return nil, errors.Join(errors.New("failed to decode fulu submit block request"), err)
		}
		res.Fulu.SignedBlock.Message.Body.ExecutionPayload = bundle.Fulu.ExecutionPayload
		res.Fulu.Blobs = make([]deneb.Blob, len(bundle.Fulu.BlobsBundle.Blobs))
		for i := range bundle.Fulu.BlobsBundle.Blobs {
			res.Fulu.Blobs[i] = bundle.Fulu.BlobsBundle.Blobs[i]
		}
		res.Fulu.KZGProofs = make([]deneb.KZGProof, len(bundle.Fulu.BlobsBundle.Proofs))
		for i := range bundle.Fulu.BlobsBundle.Proofs {
			res.Fulu.KZGProofs[i] = bundle.Fulu.BlobsBundle.Proofs[i]
		}
	}

	return &api.Response[*consensusapi.VersionedSignedProposal]{
		Data:     res,
		Metadata: metadataFromHeaders(httpResponse.headers),
	}, nil
}
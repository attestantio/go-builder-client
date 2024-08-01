// Copyright © 2022  2024 Attestant Limited.
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

package client

import (
	"context"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is the service providing a connection to an MEV relay.
type Service interface {
	// Name returns the name of the builder implementation.
	Name() string

	// Address returns the address of the builder.
	Address() string

	// Pubkey returns the public key of the builder (if any).
	Pubkey() *phase0.BLSPubKey
}

// BuilderBidProvider is the interface for a provider of builder bids.
type BuilderBidProvider interface {
	Service

	// BuilderBidProvider obtains a builder bid.
	BuilderBid(ctx context.Context,
		opts *api.BuilderBidOpts,
	) (
		*api.Response[*spec.VersionedSignedBuilderBid],
		error,
	)
}

// ValidatorRegistrationsSubmitter is the interface for a submitter of validator registrations.
type ValidatorRegistrationsSubmitter interface {
	Service

	// SubmitValidatorRegistrations submits validator registrations.
	SubmitValidatorRegistrations(ctx context.Context,
		opts *api.SubmitValidatorRegistrationsOpts,
	) error
}

// UnblindedProposalProvider is the interface for unblinded proposals.
type UnblindedProposalProvider interface {
	Service

	// UnblindProposal unblinds a proposal.
	UnblindProposal(ctx context.Context,
		opts *api.UnblindProposalOpts,
	) (
		*api.Response[*consensusapi.VersionedSignedProposal],
		error,
	)
}

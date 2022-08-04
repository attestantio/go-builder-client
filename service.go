// Copyright © 2022 Attestant Limited.
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
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is the service providing a connection to an builder client.
type Service interface {
	// Name returns the name of the client implementation.
	Name() string

	// Address returns the address of the client.
	Address() string
}

// BuilderBidProvider is the interface for a provider of builder bids.
type BuilderBidProvider interface {
	Service

	// BuilderBidProvider obtains a builder bid.
	BuilderBid(ctx context.Context,
		slot phase0.Slot,
		parentHash phase0.Hash32,
		pubKey phase0.BLSPubKey,
	) (
		*spec.VersionedSignedBuilderBid,
		error,
	)
}

// ValidatorRegistrationsSubmitter is the interface for a submitter of validator registrations.
type ValidatorRegistrationsSubmitter interface {
	Service

	// SubmitValidatorRegistrations submits validator registrations.
	SubmitValidatorRegistrations(ctx context.Context, registrations []*api.VersionedSignedValidatorRegistration) error
}

// UnblindedBlockProvider is the interface for a provider of unblinded blocks.
type UnblindedBlockProvider interface {
	Service

	// UnblindBlock unblinds a block.
	UnblindBlock(ctx context.Context,
		block *consensusapi.VersionedSignedBlindedBeaconBlock,
	) (
		*consensusspec.VersionedSignedBeaconBlock,
		error,
	)
}

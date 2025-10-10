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

package spec

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"
	"github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	consensuselectra "github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
)

// VersionedSubmitBlockRequest contains a versioned signed builder bid.
type VersionedSubmitBlockRequest struct {
	Version   consensusspec.DataVersion
	Bellatrix *bellatrix.SubmitBlockRequest
	Capella   *capella.SubmitBlockRequest
	Deneb     *deneb.SubmitBlockRequest
	Electra   *electra.SubmitBlockRequest
	Fulu      *fulu.SubmitBlockRequest
}

// IsEmpty returns true if there is no request.
func (v *VersionedSubmitBlockRequest) IsEmpty() bool {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		return v.Bellatrix == nil
	case consensusspec.DataVersionCapella:
		return v.Capella == nil
	case consensusspec.DataVersionDeneb:
		return v.Deneb == nil
	case consensusspec.DataVersionElectra:
		return v.Electra == nil
	case consensusspec.DataVersionFulu:
		return v.Fulu == nil
	default:
		return true
	}
}

// Slot returns the slot of the request.
func (v *VersionedSubmitBlockRequest) Slot() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return 0, errors.New("no data message")
		}

		return v.Bellatrix.Message.Slot, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return 0, errors.New("no data message")
		}

		return v.Capella.Message.Slot, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return 0, errors.New("no data message")
		}

		return v.Deneb.Message.Slot, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return 0, errors.New("no data message")
		}

		return v.Electra.Message.Slot, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return 0, errors.New("no data message")
		}

		return v.Fulu.Message.Slot, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// BlockHash returns the block hash of the request.
func (v *VersionedSubmitBlockRequest) BlockHash() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.BlockHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Capella.Message.BlockHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Deneb.Message.BlockHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Electra.Message.BlockHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Fulu.Message.BlockHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// Builder returns the builder of the request.
func (v *VersionedSubmitBlockRequest) Builder() (phase0.BLSPubKey, error) {
	if v == nil {
		return phase0.BLSPubKey{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.BuilderPubkey, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Capella.Message.BuilderPubkey, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Deneb.Message.BuilderPubkey, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Electra.Message.BuilderPubkey, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Fulu.Message.BuilderPubkey, nil
	default:
		return phase0.BLSPubKey{}, errors.New("unsupported version")
	}
}

// ProposerFeeRecipient returns the proposer fee recipient of the request.
func (v *VersionedSubmitBlockRequest) ProposerFeeRecipient() (consensusbellatrix.ExecutionAddress, error) {
	if v == nil {
		return consensusbellatrix.ExecutionAddress{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.ProposerFeeRecipient, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}

		return v.Capella.Message.ProposerFeeRecipient, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}

		return v.Deneb.Message.ProposerFeeRecipient, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}

		return v.Electra.Message.ProposerFeeRecipient, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}

		return v.Fulu.Message.ProposerFeeRecipient, nil
	default:
		return consensusbellatrix.ExecutionAddress{}, errors.New("unsupported version")
	}
}

// ProposerPubKey returns the proposer fee recipient of the request.
func (v *VersionedSubmitBlockRequest) ProposerPubKey() (phase0.BLSPubKey, error) {
	if v == nil {
		return phase0.BLSPubKey{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.ProposerPubkey, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Capella.Message.ProposerPubkey, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Deneb.Message.ProposerPubkey, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Electra.Message.ProposerPubkey, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Fulu.Message.ProposerPubkey, nil
	default:
		return phase0.BLSPubKey{}, errors.New("unsupported version")
	}
}

// ParentHash returns the parent hash of the request.
func (v *VersionedSubmitBlockRequest) ParentHash() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.ParentHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Capella.Message.ParentHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Deneb.Message.ParentHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Electra.Message.ParentHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}

		return v.Fulu.Message.ParentHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// Value returns the value of the request.
func (v *VersionedSubmitBlockRequest) Value() (*uint256.Int, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Bellatrix.Message.Value, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Capella.Message.Value, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Deneb.Message.Value, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Electra.Message.Value, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Fulu.Message.Value, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// BidTrace returns the bid trace of the request.
func (v *VersionedSubmitBlockRequest) BidTrace() (*apiv1.BidTrace, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no data")
		}

		if v.Bellatrix.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Bellatrix.Message, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no data")
		}

		if v.Capella.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Capella.Message, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		if v.Deneb.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Deneb.Message, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Electra.Message, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.Message == nil {
			return nil, errors.New("no data message")
		}

		return v.Fulu.Message, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// Signature returns the signature of the bid.
func (v *VersionedSubmitBlockRequest) Signature() (phase0.BLSSignature, error) {
	if v == nil {
		return phase0.BLSSignature{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}

		return v.Bellatrix.Signature, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}

		return v.Capella.Signature, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}

		return v.Deneb.Signature, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}

		return v.Electra.Signature, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}

		return v.Fulu.Signature, nil
	default:
		return phase0.BLSSignature{}, errors.New("unsupported version")
	}
}

// ExecutionPayloadBlockHash returns the block hash of the payload.
func (v *VersionedSubmitBlockRequest) ExecutionPayloadBlockHash() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.BlockHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.BlockHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.BlockHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.BlockHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.BlockHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// ExecutionPayloadParentHash returns the block hash of the payload.
func (v *VersionedSubmitBlockRequest) ExecutionPayloadParentHash() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.ParentHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.ParentHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.ParentHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.ParentHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.ParentHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// PrevRandao returns the prev randao of the payload.
func (v *VersionedSubmitBlockRequest) PrevRandao() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.PrevRandao, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.PrevRandao, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.PrevRandao, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.PrevRandao, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.PrevRandao, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// GasLimit returns the prev randao of the payload.
func (v *VersionedSubmitBlockRequest) GasLimit() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.GasLimit, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.GasLimit, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.GasLimit, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.GasLimit, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.GasLimit, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// GasUsed returns the prev randao of the payload.
func (v *VersionedSubmitBlockRequest) GasUsed() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.GasUsed, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.GasUsed, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.GasUsed, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.GasUsed, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.GasUsed, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// BlockNumber returns the block number of the payload.
func (v *VersionedSubmitBlockRequest) BlockNumber() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.BlockNumber, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.BlockNumber, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.BlockNumber, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.BlockNumber, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.BlockNumber, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// Timestamp returns the timestamp of the payload.
func (v *VersionedSubmitBlockRequest) Timestamp() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.Timestamp, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.Timestamp, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.Timestamp, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.Timestamp, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.Timestamp, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// Transactions returns the transactions of the payload.
func (v *VersionedSubmitBlockRequest) Transactions() ([]consensusbellatrix.Transaction, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no data")
		}

		if v.Bellatrix.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Bellatrix.ExecutionPayload.Transactions, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.Transactions, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.Transactions, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.Transactions, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.Transactions, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// Withdrawals returns the withdrawals of the payload.
func (v *VersionedSubmitBlockRequest) Withdrawals() ([]*consensuscapella.Withdrawal, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no data")
		}

		if v.Capella.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Capella.ExecutionPayload.Withdrawals, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.Withdrawals, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.Withdrawals, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.Withdrawals, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// Blobs returns the blobs of the blobs bundle.
func (v *VersionedSubmitBlockRequest) Blobs() ([]consensusdeneb.Blob, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		if v.Deneb.BlobsBundle == nil {
			return nil, errors.New("no data blobs bundle")
		}

		return v.Deneb.BlobsBundle.Blobs, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.BlobsBundle == nil {
			return nil, errors.New("no data blobs bundle")
		}

		return v.Electra.BlobsBundle.Blobs, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.BlobsBundle == nil {
			return nil, errors.New("no data blobs bundle")
		}

		return v.Fulu.BlobsBundle.Blobs, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// BlobGasUsed returns the blob gas used of the payload.
func (v *VersionedSubmitBlockRequest) BlobGasUsed() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.BlobGasUsed, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.BlobGasUsed, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.BlobGasUsed, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// ExcessBlobGas returns the excess blob gas of the payload.
func (v *VersionedSubmitBlockRequest) ExcessBlobGas() (uint64, error) {
	if v == nil {
		return 0, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}

		if v.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Deneb.ExecutionPayload.ExcessBlobGas, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}

		if v.Electra.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.ExcessBlobGas, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}

		if v.Fulu.ExecutionPayload == nil {
			return 0, errors.New("no data execution payload")
		}

		return v.Fulu.ExecutionPayload.ExcessBlobGas, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// DepositRequests returns the deposit requests of the execution requests.
func (v *VersionedSubmitBlockRequest) DepositRequests() ([]*consensuselectra.DepositRequest, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Electra.ExecutionRequests.Deposits, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Fulu.ExecutionRequests.Deposits, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// WithdrawalRequests returns the withdrawal requests of the execution requests.
func (v *VersionedSubmitBlockRequest) WithdrawalRequests() ([]*consensuselectra.WithdrawalRequest, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Electra.ExecutionRequests.Withdrawals, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Fulu.ExecutionRequests.Withdrawals, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// ConsolidationRequests returns the consolidation requests of the execution requests.
func (v *VersionedSubmitBlockRequest) ConsolidationRequests() ([]*consensuselectra.ConsolidationRequest, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		if v.Electra.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Electra.ExecutionRequests.Consolidations, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		if v.Fulu.ExecutionRequests == nil {
			return nil, errors.New("no data execution requests")
		}

		return v.Fulu.ExecutionRequests.Consolidations, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// String returns a string version of the structure.
func (v *VersionedSubmitBlockRequest) String() string {
	if v == nil {
		return ""
	}

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

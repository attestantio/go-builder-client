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
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
)

// VersionedSignedBuilderBid contains a versioned signed builder bid.
type VersionedSignedBuilderBid struct {
	Version   consensusspec.DataVersion
	Bellatrix *bellatrix.SignedBuilderBid
	Capella   *capella.SignedBuilderBid
	Deneb     *deneb.SignedBuilderBid
	Electra   *electra.SignedBuilderBid
	Fulu      *fulu.SignedBuilderBid
}

// IsEmpty returns true if there is no bid.
func (v *VersionedSignedBuilderBid) IsEmpty() bool {
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

// Builder returns the builder of the bid.
func (v *VersionedSignedBuilderBid) Builder() (phase0.BLSPubKey, error) {
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

		return v.Bellatrix.Message.Pubkey, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Capella.Message.Pubkey, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Deneb.Message.Pubkey, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Electra.Message.Pubkey, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.BLSPubKey{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.BLSPubKey{}, errors.New("no data message")
		}

		return v.Fulu.Message.Pubkey, nil
	default:
		return phase0.BLSPubKey{}, errors.New("unsupported version")
	}
}

// Value returns the value of the bid.
func (v *VersionedSignedBuilderBid) Value() (*uint256.Int, error) {
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

// BlockNumber returns the block number of the bid.
func (v *VersionedSignedBuilderBid) BlockNumber() (uint64, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.BlockNumber, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Capella.Message.Header.BlockNumber, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.BlockNumber, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Electra.Message.Header.BlockNumber, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.BlockNumber, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// BlockHash returns the block hash of the bid.
func (v *VersionedSignedBuilderBid) BlockHash() (phase0.Hash32, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.BlockHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.BlockHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.BlockHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.BlockHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.BlockHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// ParentHash returns the parent hash of the bid.
func (v *VersionedSignedBuilderBid) ParentHash() (phase0.Hash32, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.ParentHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.ParentHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.ParentHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.ParentHash, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Hash32{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return phase0.Hash32{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.ParentHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// StateRoot returns the state root of the bid.
func (v *VersionedSignedBuilderBid) StateRoot() (phase0.Root, error) {
	if v == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Bellatrix.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Bellatrix.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.StateRoot, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.StateRoot, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.StateRoot, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.StateRoot, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.StateRoot, nil
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

// FeeRecipient returns the fee recipient of the bid.
func (v *VersionedSignedBuilderBid) FeeRecipient() (consensusbellatrix.ExecutionAddress, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.FeeRecipient, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.FeeRecipient, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.FeeRecipient, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.FeeRecipient, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return consensusbellatrix.ExecutionAddress{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.FeeRecipient, nil
	default:
		return consensusbellatrix.ExecutionAddress{}, errors.New("unsupported version")
	}
}

// Timestamp returns the timestamp of the bid.
func (v *VersionedSignedBuilderBid) Timestamp() (uint64, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.Timestamp, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Capella.Message.Header.Timestamp, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.Timestamp, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Electra.Message.Header.Timestamp, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.Timestamp, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// TransactionsRoot returns the transactions root of the bid.
func (v *VersionedSignedBuilderBid) TransactionsRoot() (phase0.Root, error) {
	if v == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Bellatrix.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Bellatrix.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.TransactionsRoot, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.TransactionsRoot, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.TransactionsRoot, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.TransactionsRoot, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.TransactionsRoot, nil
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

// MessageHashTreeRoot returns the hash tree root of the message of the bid.
func (v *VersionedSignedBuilderBid) MessageHashTreeRoot() (phase0.Root, error) {
	if v == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Bellatrix.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}

		return v.Bellatrix.Message.HashTreeRoot()
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}

		return v.Capella.Message.HashTreeRoot()
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}

		return v.Deneb.Message.HashTreeRoot()
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}

		return v.Electra.Message.HashTreeRoot()
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}

		return v.Fulu.Message.HashTreeRoot()
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

// HeaderHashTreeRoot returns the hash tree root of the header of the bid.
func (v *VersionedSignedBuilderBid) HeaderHashTreeRoot() (phase0.Root, error) {
	if v == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Bellatrix.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Bellatrix.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.HashTreeRoot()
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Capella.Message.Header.HashTreeRoot()
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.HashTreeRoot()
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Electra.Message.Header.HashTreeRoot()
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.HashTreeRoot()
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

// BlockGasLimit returns the block gas limit of the header of the bid.
func (v *VersionedSignedBuilderBid) BlockGasLimit() (uint64, error) {
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
		if v.Bellatrix.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Bellatrix.Message.Header.GasLimit, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Capella.Message.Header.GasLimit, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return 0, errors.New("no data")
		}
		if v.Deneb.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Deneb.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Deneb.Message.Header.GasLimit, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return 0, errors.New("no data")
		}
		if v.Electra.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Electra.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Electra.Message.Header.GasLimit, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return 0, errors.New("no data")
		}
		if v.Fulu.Message == nil {
			return 0, errors.New("no data message")
		}
		if v.Fulu.Message.Header == nil {
			return 0, errors.New("no data message header")
		}

		return v.Fulu.Message.Header.GasLimit, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// Signature returns the signature of the bid.
func (v *VersionedSignedBuilderBid) Signature() (phase0.BLSSignature, error) {
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

// String returns a string version of the structure.
func (v *VersionedSignedBuilderBid) String() string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

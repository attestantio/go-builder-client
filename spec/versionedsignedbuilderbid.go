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
}

// IsEmpty returns true if there is no bid.
func (v *VersionedSignedBuilderBid) IsEmpty() bool {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		return v.Bellatrix == nil
	case consensusspec.DataVersionCapella:
		return v.Capella == nil
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
	default:
		return nil, errors.New("unsupported version")
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
		if v.Bellatrix.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return v.Bellatrix.Message.HashTreeRoot()
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
		return v.Capella.Message.HashTreeRoot()
	default:
		return phase0.Root{}, errors.New("unsupported version")
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

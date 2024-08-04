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

package api

import (
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	consensuselectra "github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// VersionedSubmitBlindedBlockResponse contains a versioned SubmitBlindedBlockResponse.
type VersionedSubmitBlindedBlockResponse struct {
	Version   consensusspec.DataVersion
	Bellatrix *bellatrix.ExecutionPayload
	Capella   *capella.ExecutionPayload
	Deneb     *deneb.ExecutionPayloadAndBlobsBundle
	Electra   *electra.ExecutionPayloadAndBlobsBundle
}

// IsEmpty returns true if there is no payload.
func (v *VersionedSubmitBlindedBlockResponse) IsEmpty() bool {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:

		return v.Bellatrix == nil
	case consensusspec.DataVersionCapella:
		return v.Capella == nil
	case consensusspec.DataVersionDeneb:
		return v.Deneb == nil
	case consensusspec.DataVersionElectra:
		return v.Electra == nil
	default:
		return true
	}
}

func (v *VersionedSubmitBlindedBlockResponse) BlockHash() (phase0.Hash32, error) {
	if v == nil {
		return phase0.Hash32{}, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		return v.Bellatrix.BlockHash, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}

		return v.Capella.BlockHash, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}

		return v.Deneb.ExecutionPayload.BlockHash, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Electra.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}

		return v.Electra.ExecutionPayload.BlockHash, nil
	default:
		return phase0.Hash32{}, errors.New("unsupported version")
	}
}

// Transactions returns the transactions in the execution payload.
func (v *VersionedSubmitBlindedBlockResponse) Transactions() ([]bellatrix.Transaction, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no data")
		}

		return v.Bellatrix.Transactions, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no data")
		}

		return v.Capella.Transactions, nil
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}
		if v.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}

		return v.Deneb.ExecutionPayload.Transactions, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}
		if v.Electra.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}

		return v.Electra.ExecutionPayload.Transactions, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// Blobs returns the blobs of the blobs bundle.
func (v *VersionedSubmitBlindedBlockResponse) Blobs() ([]consensusdeneb.Blob, error) {
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
	default:
		return nil, errors.New("unsupported version")
	}
}

// BlobGasUsed returns the blob gas used of the payload.
func (v *VersionedSubmitBlindedBlockResponse) BlobGasUsed() (uint64, error) {
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
	default:
		return 0, errors.New("unsupported version")
	}
}

// ExcessBlobGas returns the excess blob gas of the payload.
func (v *VersionedSubmitBlindedBlockResponse) ExcessBlobGas() (uint64, error) {
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
	default:
		return 0, errors.New("unsupported version")
	}
}

// DepositRequests returns the deposit receipts of the execution payload.
func (v *VersionedSubmitBlindedBlockResponse) DepositRequests() ([]*consensuselectra.DepositRequest, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}
		if v.Electra.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.DepositRequests, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// WithdrawalRequests returns the execution layer withdrawal requests of the execution payload.
func (v *VersionedSubmitBlindedBlockResponse) WithdrawalRequests() ([]*consensuselectra.WithdrawalRequest, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}
		if v.Electra.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}

		return v.Electra.ExecutionPayload.WithdrawalRequests, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

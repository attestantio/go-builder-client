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
	"github.com/attestantio/go-builder-client/api/fulu"
	"github.com/attestantio/go-eth2-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// VersionedSubmitBlindedBlockResponse contains a versioned SubmitBlindedBlockResponse.
type VersionedSubmitBlindedBlockResponse struct {
	Version   consensusspec.DataVersion
	Bellatrix *bellatrix.ExecutionPayload
	Capella   *capella.ExecutionPayload
	Deneb     *deneb.ExecutionPayloadAndBlobsBundle
	Electra   *deneb.ExecutionPayloadAndBlobsBundle
	Fulu      *fulu.ExecutionPayloadAndBlobsBundle
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
	case consensusspec.DataVersionFulu:
		return v.Fulu == nil
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
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if v.Fulu.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}

		return v.Fulu.ExecutionPayload.BlockHash, nil
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
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}
		if v.Fulu.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}

		return v.Fulu.ExecutionPayload.Transactions, nil
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

// BlobsBundle returns the blobs bundle.
func (v *VersionedSubmitBlindedBlockResponse) BlobsBundle() (*VersionedBlobsBundle, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}
	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		return &VersionedBlobsBundle{
			Version: spec.DataVersionDeneb,
			Deneb:   v.Deneb.BlobsBundle,
		}, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		return &VersionedBlobsBundle{
			Version: spec.DataVersionElectra,
			Electra: v.Electra.BlobsBundle,
		}, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		return &VersionedBlobsBundle{
			Version: spec.DataVersionFulu,
			Fulu:    v.Fulu.BlobsBundle,
		}, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

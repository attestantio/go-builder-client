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

package api

import (
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/fulu"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/pkg/errors"
)

// VersionedBlobsBundle contains a versioned BlobsBundle.
type VersionedBlobsBundle struct {
	Version consensusspec.DataVersion
	Deneb   *deneb.BlobsBundle
	Electra *deneb.BlobsBundle
	Fulu    *fulu.BlobsBundle
}

func (v *VersionedBlobsBundle) Commitments() ([]consensusdeneb.KZGCommitment, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		return v.Deneb.Commitments, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		return v.Electra.Commitments, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		return v.Fulu.Commitments, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (v *VersionedBlobsBundle) Proofs() ([]consensusdeneb.KZGProof, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		return v.Deneb.Proofs, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		return v.Electra.Proofs, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		return v.Fulu.Proofs, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (v *VersionedBlobsBundle) Blobs() ([]consensusdeneb.Blob, error) {
	if v == nil {
		return nil, errors.New("nil struct")
	}

	switch v.Version {
	case consensusspec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no data")
		}

		return v.Deneb.Blobs, nil
	case consensusspec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no data")
		}

		return v.Electra.Blobs, nil
	case consensusspec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no data")
		}

		return v.Fulu.Blobs, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

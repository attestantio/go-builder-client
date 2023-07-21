// Copyright © 2023 Attestant Limited.
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

package deneb

import (
	"encoding/json"

	"github.com/attestantio/go-eth2-client/codecs"
	"github.com/pkg/errors"
)

// blindedBlobsBundleJSON is the spec representation of the struct.
type blindedBlobsBundleJSON struct {
	Commitments []string `json:"commitments"`
	Proofs      []string `json:"proofs"`
	BlobRoots   []string `json:"blob_roots"`
}

// MarshalJSON implements json.Marshaler.
func (b *BlindedBlobsBundle) MarshalJSON() ([]byte, error) {
	blobKzgCommitments := make([]string, len(b.Commitments))
	for i := range b.Commitments {
		blobKzgCommitments[i] = b.Commitments[i].String()
	}

	blobKzgProofs := make([]string, len(b.Proofs))
	for i := range b.Proofs {
		blobKzgProofs[i] = b.Proofs[i].String()
	}

	blobRoots := make([]string, len(b.BlobRoots))
	for i := range b.BlobRoots {
		blobRoots[i] = b.BlobRoots[i].String()
	}

	return json.Marshal(&blindedBlobsBundleJSON{
		Commitments: blobKzgCommitments,
		Proofs:      blobKzgProofs,
		BlobRoots:   blobRoots,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BlindedBlobsBundle) UnmarshalJSON(input []byte) error {
	raw, err := codecs.RawJSON(&blindedBlobsBundleJSON{}, input)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(raw["commitments"], &b.Commitments); err != nil {
		return errors.Wrap(err, "commitments")
	}

	if err := json.Unmarshal(raw["proofs"], &b.Proofs); err != nil {
		return errors.Wrap(err, "proofs")
	}

	if err := json.Unmarshal(raw["blob_roots"], &b.BlobRoots); err != nil {
		return errors.Wrap(err, "blob_roots")
	}

	return nil
}

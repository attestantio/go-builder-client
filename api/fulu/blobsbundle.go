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

package fulu

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/goccy/go-yaml"
)

// CellsPerExtBlob is the number of cells per extended blob for PeerDAS (EIP-7594).
const CellsPerExtBlob = 128

// BlobsBundle is the structure used to store the blobs bundle for Fulu.
// Fulu implements PeerDAS (EIP-7594) which uses cell proofs instead of blob proofs.
type BlobsBundle struct {
	Commitments []deneb.KZGCommitment `ssz-max:"4096"   ssz-size:"?,48"`
	// In Fulu, we have CellsPerExtBlob proofs per blob (128 proofs per blob).
	Proofs []deneb.KZGProof `ssz-max:"524288" ssz-size:"?,48"` // 4096 blobs * 128 proofs per blob = 524288
	Blobs  []deneb.Blob     `ssz-max:"4096"   ssz-size:"?,131072"`
}

// String returns a string version of the structure.
func (b *BlobsBundle) String() string {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

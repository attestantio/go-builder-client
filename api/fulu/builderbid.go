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
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/holiman/uint256"
)

// BuilderBid represents a BuilderBid.
type BuilderBid struct {
	Header             *deneb.ExecutionPayloadHeader
	BlobKZGCommitments []deneb.KZGCommitment `ssz-max:"4096" ssz-size:"?,48"`
	ExecutionRequests  *electra.ExecutionRequests
	Value              *uint256.Int     `ssz-size:"32"`
	Pubkey             phase0.BLSPubKey `ssz-size:"48"`
}

// String returns a string version of the structure.
func (b *BuilderBid) String() string {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

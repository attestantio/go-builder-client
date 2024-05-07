// Copyright © 2024 Attestant Limited.
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

package electra

import (
	"bytes"
	"math/big"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/goccy/go-yaml"
)

// builderBidYAML is the spec representation of the struct.
type builderBidYAML struct {
	Header             *electra.ExecutionPayloadHeader `yaml:"header"`
	BlobKZGCommitments []deneb.KZGCommitment           `yaml:"blob_kzg_commitments"`
	Value              *big.Int                        `yaml:"value"`
	Pubkey             string                          `yaml:"pubkey"`
}

// MarshalYAML implements yaml.Marshaler.
func (b *BuilderBid) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&builderBidYAML{
		Header:             b.Header,
		BlobKZGCommitments: b.BlobKZGCommitments,
		Value:              b.Value.ToBig(),
		Pubkey:             b.Pubkey.String(),
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BuilderBid) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data builderBidJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return b.unpack(&data)
}

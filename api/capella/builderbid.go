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

package capella

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// BuilderBid represents a BuilderBid.
type BuilderBid struct {
	Header *capella.ExecutionPayloadHeader
	Value  *uint256.Int     `ssz-size:"32"`
	Pubkey phase0.BLSPubKey `ssz-size:"48"`
}

// builderBidJSON is the spec representation of the struct.
type builderBidJSON struct {
	Header *capella.ExecutionPayloadHeader `json:"header"`
	Value  string                          `json:"value"`
	Pubkey string                          `json:"pubkey"`
}

// builderBidYAML is the spec representation of the struct.
type builderBidYAML struct {
	Header *capella.ExecutionPayloadHeader `yaml:"header"`
	Value  *big.Int                        `yaml:"value"`
	Pubkey string                          `yaml:"pubkey"`
}

// MarshalJSON implements json.Marshaler.
func (b *BuilderBid) MarshalJSON() ([]byte, error) {
	return json.Marshal(&builderBidJSON{
		Header: b.Header,
		Value:  fmt.Sprintf("%d", b.Value),
		Pubkey: fmt.Sprintf("%#x", b.Pubkey),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BuilderBid) UnmarshalJSON(input []byte) error {
	var data builderBidJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	return b.unpack(&data)
}

func (b *BuilderBid) unpack(data *builderBidJSON) error {
	if data.Header == nil {
		return errors.New("header missing")
	}
	b.Header = data.Header

	if data.Value == "" {
		return errors.New("value missing")
	}
	value, success := new(big.Int).SetString(data.Value, 10)
	if !success {
		return errors.New("invalid value for value")
	}
	if value.Sign() == -1 {
		return errors.New("value cannot be negative")
	}
	var overflow bool
	b.Value, overflow = uint256.FromBig(value)
	if overflow {
		return errors.New("value overflow")
	}

	if data.Pubkey == "" {
		return errors.New("public key missing")
	}
	pubKey, err := hex.DecodeString(strings.TrimPrefix(data.Pubkey, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for public key")
	}
	if len(pubKey) != phase0.PublicKeyLength {
		return errors.New("incorrect length for public key")
	}
	copy(b.Pubkey[:], pubKey)

	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (b *BuilderBid) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&builderBidYAML{
		Header: b.Header,
		Value:  b.Value.ToBig(),
		Pubkey: fmt.Sprintf("%#x", b.Pubkey),
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

// String returns a string version of the structure.
func (b *BuilderBid) String() string {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return string(data)
}

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

package bellatrix

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// SignedBuilderBid represents a SignedBuilderBid.
type SignedBuilderBid struct {
	Message   *BuilderBid
	Signature phase0.BLSSignature `ssz-size:"96"`
}

// signedBuilderBidJSON is the spec representation of the struct.
type signedBuilderBidJSON struct {
	Message   *BuilderBid `json:"message"`
	Signature string      `json:"signature"`
}

// signedBuilderBidYAML is the spec representation of the struct.
type signedBuilderBidYAML struct {
	Message   *BuilderBid `yaml:"message"`
	Signature string      `yaml:"signature"`
}

// MarshalJSON implements json.Marshaler.
func (s *SignedBuilderBid) MarshalJSON() ([]byte, error) {
	return json.Marshal(&signedBuilderBidJSON{
		Message:   s.Message,
		Signature: fmt.Sprintf("%#x", s.Signature),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SignedBuilderBid) UnmarshalJSON(input []byte) error {
	var data signedBuilderBidJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return s.unpack(&data)
}

// MarshalYAML implements yaml.Marshaler.
func (s *SignedBuilderBid) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&signedBuilderBidYAML{
		Message:   s.Message,
		Signature: fmt.Sprintf("%#x", s.Signature),
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SignedBuilderBid) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data signedBuilderBidJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return s.unpack(&data)
}

// String returns a string version of the structure.
func (s *SignedBuilderBid) String() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

func (s *SignedBuilderBid) unpack(data *signedBuilderBidJSON) error {
	if data.Message == nil {
		return errors.New("message missing")
	}

	s.Message = data.Message
	if data.Signature == "" {
		return errors.New("signature missing")
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(data.Signature, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature")
	}

	if len(signature) != phase0.SignatureLength {
		return errors.New("incorrect length for signature")
	}

	copy(s.Signature[:], signature)

	return nil
}

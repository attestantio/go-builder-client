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

package capella

import (
	"bytes"
	"fmt"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/goccy/go-yaml"
)

// submitBlockRequestYAML is the spec representation of the struct.
type submitBlockRequestYAML struct {
	Message          *apiv1.BidTrace           `yaml:"message"`
	ExecutionPayload *capella.ExecutionPayload `yaml:"execution_payload"`
	Signature        string                    `yaml:"signature"`
}

// MarshalYAML implements yaml.Marshaler.
func (s *SubmitBlockRequest) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&submitBlockRequestYAML{
		Message:          s.Message,
		Signature:        fmt.Sprintf("%#x", s.Signature),
		ExecutionPayload: s.ExecutionPayload,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SubmitBlockRequest) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data submitBlockRequestJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return s.unpack(&data)
}

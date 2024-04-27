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

	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/goccy/go-yaml"
)

// executionPayloadAndBlobsBundleYAML is the spec representation of the struct.
type executionPayloadAndBlobsBundleYAML struct {
	ExecutionPayload *electra.ExecutionPayload `yaml:"execution_payload"`
	BlobsBundle      *deneb.BlobsBundle        `yaml:"blobs_bundle"`
}

// MarshalYAML implements yaml.Marshaler.
func (e *ExecutionPayloadAndBlobsBundle) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&executionPayloadAndBlobsBundleYAML{
		ExecutionPayload: e.ExecutionPayload,
		BlobsBundle:      e.BlobsBundle,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (e *ExecutionPayloadAndBlobsBundle) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data executionPayloadAndBlobsBundleJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}
	return e.unpack(&data)
}

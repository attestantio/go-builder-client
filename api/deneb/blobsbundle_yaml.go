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
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// blobsBundleYAML is the YAML representation of a blob bundle.
type blobsBundleYAML struct {
	Commitments []string `yaml:"commitments"`
	Proofs      []string `yaml:"proofs"`
	Blobs       []string `yaml:"blobs"`
}

// MarshalYAML implements yaml.Marshaler.
func (b *BlobsBundle) MarshalYAML() ([]byte, error) {
	blobKzgCommitments := make([]string, len(b.Commitments))
	for i := range b.Commitments {
		blobKzgCommitments[i] = b.Commitments[i].String()
	}

	blobKzgProofs := make([]string, len(b.Proofs))
	for i := range b.Proofs {
		blobKzgProofs[i] = b.Proofs[i].String()
	}

	blobs := make([]string, len(b.Blobs))
	for i := range b.Blobs {
		blobs[i] = fmt.Sprintf("%#x", b.Blobs[i])
	}

	yamlBytes, err := yaml.MarshalWithOptions(&blobsBundleYAML{
		Commitments: blobKzgCommitments,
		Proofs:      blobKzgProofs,
		Blobs:       blobs,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BlobsBundle) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data blobsBundleJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "failed to unmarshal YAML")
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	return b.UnmarshalJSON(jsonBytes)
}

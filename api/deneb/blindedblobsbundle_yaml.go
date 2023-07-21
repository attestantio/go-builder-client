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

	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// blindedBlobsBundleYAML is the YAML representation of a blob bundle.
type blindedBlobsBundleYAML struct {
	Commitments []string `yaml:"commitments"`
	Proofs      []string `yaml:"proofs"`
	BlobRoots   []string `yaml:"blob_roots"`
}

// MarshalYAML implements yaml.Marshaler.
func (b *BlindedBlobsBundle) MarshalYAML() ([]byte, error) {
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

	yamlBytes, err := yaml.MarshalWithOptions(&blindedBlobsBundleYAML{
		Commitments: blobKzgCommitments,
		Proofs:      blobKzgProofs,
		BlobRoots:   blobRoots,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BlindedBlobsBundle) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data blindedBlobsBundleJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "failed to unmarshal YAML")
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	return b.UnmarshalJSON(bytes)
}

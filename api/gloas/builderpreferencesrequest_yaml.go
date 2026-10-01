// Copyright © 2026 Attestant Limited.
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

package gloas

import (
	"bytes"

	"github.com/goccy/go-yaml"
)

// builderPreferencesRequestYAML is the spec representation of the struct.
type builderPreferencesRequestYAML struct {
	Preferences *BuilderPreferences       `yaml:"preferences"`
	Auth        *SignedBuilderRequestAuth `yaml:"auth"`
}

// MarshalYAML implements yaml.Marshaler.
func (b *BuilderPreferencesRequest) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&builderPreferencesRequestYAML{
		Preferences: b.Preferences,
		Auth:        b.Auth,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BuilderPreferencesRequest) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data builderPreferencesRequestJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return b.unpack(&data)
}

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

package gloas_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-builder-client/api/gloas"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestBuilderPreferencesRequestJSON(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name: "Empty",
			err:  "unexpected end of JSON input",
		},
		{
			name:  "JSONBad",
			input: []byte("[]"),
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type gloas.builderPreferencesRequestJSON",
		},
		{
			name:  "PreferencesMissing",
			input: []byte(`{"auth":{"message":{"data":"0x0102","slot":"1"},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}}`),
			err:   "preferences missing",
		},
		{
			name:  "PreferencesWrongType",
			input: []byte(`{"preferences":true,"auth":{"message":{"data":"0x0102","slot":"1"},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type gloas.builderPreferencesJSON",
		},
		{
			name:  "PreferencesInvalid",
			input: []byte(`{"preferences":{},"auth":{"message":{"data":"0x0102","slot":"1"},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}}`),
			err:   "invalid JSON: max execution payment missing",
		},
		{
			name:  "AuthMissing",
			input: []byte(`{"preferences":{"max_execution_payment":"12345"}}`),
			err:   "auth missing",
		},
		{
			name:  "AuthWrongType",
			input: []byte(`{"preferences":{"max_execution_payment":"12345"},"auth":true}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type gloas.signedBuilderRequestAuthJSON",
		},
		{
			name:  "AuthInvalid",
			input: []byte(`{"preferences":{"max_execution_payment":"12345"},"auth":{}}`),
			err:   "invalid JSON: message missing",
		},
		{
			name:  "Good",
			input: []byte(`{"preferences":{"max_execution_payment":"12345"},"auth":{"message":{"data":"0x0102","slot":"1"},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderPreferencesRequest
			err := json.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := json.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}

func TestBuilderPreferencesRequestYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{preferences: {max_execution_payment: 12345}, auth: {message: {data: '0x0102', slot: 1}, signature: '0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderPreferencesRequest
			err := yaml.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := yaml.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, string(rt), res.String())
				rt = bytes.TrimSuffix(rt, []byte("\n"))
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}

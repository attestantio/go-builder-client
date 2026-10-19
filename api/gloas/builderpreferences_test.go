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

func TestBuilderPreferencesJSON(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type gloas.builderPreferencesJSON",
		},
		{
			name:  "MaxExecutionPaymentMissing",
			input: []byte(`{}`),
			err:   "max execution payment missing",
		},
		{
			name:  "MaxExecutionPaymentWrongType",
			input: []byte(`{"max_execution_payment":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field builderPreferencesJSON.max_execution_payment of type string",
		},
		{
			name:  "MaxExecutionPaymentInvalid",
			input: []byte(`{"max_execution_payment":"-1"}`),
			err:   "invalid value for max execution payment: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "Good",
			input: []byte(`{"max_execution_payment":"12345"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderPreferences
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

func TestBuilderPreferencesYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{max_execution_payment: 12345}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderPreferences
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

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

func TestSignedBuilderRequestAuthJSON(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type gloas.signedBuilderRequestAuthJSON",
		},
		{
			name:  "MessageMissing",
			input: []byte(`{"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}`),
			err:   "message missing",
		},
		{
			name:  "MessageWrongType",
			input: []byte(`{"message":true,"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type gloas.builderRequestAuthJSON",
		},
		{
			name:  "MessageInvalid",
			input: []byte(`{"message":{},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}`),
			err:   "invalid JSON: data missing",
		},
		{
			name:  "SignatureMissing",
			input: []byte(`{"message":{"data":"0x0102","slot":"1"}}`),
			err:   "signature missing",
		},
		{
			name:  "SignatureWrongType",
			input: []byte(`{"message":{"data":"0x0102","slot":"1"},"signature":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field signedBuilderRequestAuthJSON.signature of type string",
		},
		{
			name:  "SignatureInvalid",
			input: []byte(`{"message":{"data":"0x0102","slot":"1"},"signature":"invalid"}`),
			err:   "invalid value for signature: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "SignatureIncorrectLength",
			input: []byte(`{"message":{"data":"0x0102","slot":"1"},"signature":"0x0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}`),
			err:   "incorrect length for signature",
		},
		{
			name:  "Good",
			input: []byte(`{"message":{"data":"0x0102","slot":"1"},"signature":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.SignedBuilderRequestAuth
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

func TestSignedBuilderRequestAuthYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{message: {data: '0x0102', slot: 1}, signature: '0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.SignedBuilderRequestAuth
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

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
	"fmt"
	"strings"
	"testing"

	"github.com/attestantio/go-builder-client/api/gloas"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestBuilderRequestAuthJSON(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type gloas.builderRequestAuthJSON",
		},
		{
			name:  "DataMissing",
			input: []byte(`{"slot":"1"}`),
			err:   "data missing",
		},
		{
			name:  "DataWrongType",
			input: []byte(`{"data":true,"slot":"1"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field builderRequestAuthJSON.data of type string",
		},
		{
			name:  "DataInvalid",
			input: []byte(`{"data":"invalid","slot":"1"}`),
			err:   "invalid value for data: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "DataZeroLength",
			input: []byte(`{"data":"0x","slot":"1"}`),
			err:   "data missing",
		},
		{
			name:  "DataTooLong",
			input: []byte(fmt.Sprintf(`{"data":"0x%s","slot":"1"}`, strings.Repeat("01", gloas.MaxBuilderAuthDataSize+1))),
			err:   "data too long",
		},
		{
			name:  "SlotMissing",
			input: []byte(`{"data":"0x0102"}`),
			err:   "slot missing",
		},
		{
			name:  "SlotWrongType",
			input: []byte(`{"data":"0x0102","slot":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field builderRequestAuthJSON.slot of type string",
		},
		{
			name:  "SlotInvalid",
			input: []byte(`{"data":"0x0102","slot":"-1"}`),
			err:   "invalid value for slot: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "Good",
			input: []byte(`{"data":"0x0102","slot":"1"}`),
		},
		{
			name:  "GoodMaxData",
			input: []byte(fmt.Sprintf(`{"data":"0x%s","slot":"1"}`, strings.Repeat("01", gloas.MaxBuilderAuthDataSize))),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderRequestAuth
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

func TestBuilderRequestAuthYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name:  "DataZeroLength",
			input: []byte(`{data: '0x', slot: 1}`),
			err:   "data missing",
		},
		{
			name:  "Good",
			input: []byte(`{data: '0x0102', slot: 1}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res gloas.BuilderRequestAuth
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

func TestBuilderRequestAuthMarshalEmptyData(t *testing.T) {
	obj := &gloas.BuilderRequestAuth{Slot: 1}

	_, err := obj.MarshalJSON()
	require.EqualError(t, err, "data missing")

	_, err = obj.MarshalYAML()
	require.EqualError(t, err, "data missing")
}

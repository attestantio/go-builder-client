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

package deneb_test

import (
	"encoding/json"
	"testing"

	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestBlindedBlobsBundleJSON(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type map[string]json.RawMessage",
		},
		{
			name:  "CommitmentsMissing",
			input: []byte(`{"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "commitments: missing",
		},
		{
			name:  "CommitmentsWrongType",
			input: []byte(`{"commitments":true,"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "commitments: json: cannot unmarshal bool into Go value of type []deneb.KzgCommitment",
		},
		{
			name:  "CommitmentWrongType",
			input: []byte(`{"commitments":[true],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "commitments: invalid prefix",
		},
		{
			name:  "CommitmentInvalid",
			input: []byte(`{"commitments":["0xi5cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "commitments: invalid value i5cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "CommitmentIncorrectLength",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f47"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "commitments: incorrect length",
		},
		{
			name:  "ProofsMissing",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "proofs: missing",
		},
		{
			name:  "ProofsWrongType",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":true,"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "proofs: json: cannot unmarshal bool into Go value of type []deneb.KzgProof",
		},
		{
			name:  "ProofWrongType",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":[true],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "proofs: invalid prefix",
		},
		{
			name:  "ProofInvalid",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xi6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "proofs: invalid value i6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "ProofIncorrectLength",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
			err:   "proofs: incorrect length",
		},
		{
			name:  "BlobRootsMissing",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"]}`),
			err:   "blob_roots: missing",
		},
		{
			name:  "BlobRootsWrongType",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":true}`),
			err:   "blob_roots: json: cannot unmarshal bool into Go value of type []phase0.Root",
		},
		{
			name:  "BlobRootWrongType",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":[true]}`),
			err:   "blob_roots: invalid prefix",
		},
		{
			name:  "BlobRootInvalid",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0xic1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29"]}`),
			err:   "blob_roots: invalid value ic1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "BlobRootIncorrectLength",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc2"]}`),
			err:   "blob_roots: incorrect length",
		},
		{
			name:  "Good",
			input: []byte(`{"commitments":["0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f","0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"],"proofs":["0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff","0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff"],"blob_roots":["0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29","0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df"]}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res deneb.BlindedBlobsBundle
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

func TestBlindedBlobsBundleYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		root  []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{commitments: ['0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f', '0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929'], proofs: ['0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff', '0xc6e27a3ae80243ba7ea88eab107a0675020e0745d75ab6a1553691007a50f7f99f597693ac33ae3cea63bf0b90a734ff'], blob_roots: ['0x3c1820c62034fc45c10abc983dbce08de28f303192dea32371a902b3e6a1fc29','0xba4d784293df28bab771a14df58cdbed9d8d64afd0ddf1c52dff3e25fcdd51df']}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res deneb.BlindedBlobsBundle
			err := yaml.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := yaml.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, testYAMLFormat([]byte(res.String())), testYAMLFormat(rt))
				assert.Equal(t, testYAMLFormat(test.input), testYAMLFormat(rt))
			}
		})
	}
}

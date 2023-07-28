// Copyright © 2022 Attestant Limited.
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

package api_test

import (
	"testing"

	"github.com/attestantio/go-builder-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestVersionedExecutionPayloadEmpty(t *testing.T) {
	empty := &api.VersionedExecutionPayload{
		Version: consensusspec.DataVersionBellatrix,
	}
	require.True(t, empty.IsEmpty())

	mismatch1 := &api.VersionedExecutionPayload{
		Version: consensusspec.DataVersionBellatrix,
		Capella: &capella.ExecutionPayload{},
	}
	require.True(t, mismatch1.IsEmpty())

	mismatch2 := &api.VersionedExecutionPayload{
		Version:   consensusspec.DataVersionCapella,
		Bellatrix: &bellatrix.ExecutionPayload{},
	}
	require.True(t, mismatch2.IsEmpty())

	mismatch3 := &api.VersionedExecutionPayload{
		Version: consensusspec.DataVersionDeneb,
		Capella: &capella.ExecutionPayload{},
	}
	require.True(t, mismatch3.IsEmpty())

	incorrectVersion := &api.VersionedExecutionPayload{
		Version:   consensusspec.DataVersionDeneb,
		Bellatrix: &bellatrix.ExecutionPayload{},
		Capella:   &capella.ExecutionPayload{},
	}
	require.True(t, incorrectVersion.IsEmpty())

	notEmpty := &api.VersionedExecutionPayload{
		Version: consensusspec.DataVersionDeneb,
		Deneb:   &deneb.ExecutionPayload{},
	}
	require.False(t, notEmpty.IsEmpty())
}

func TestVersionedExecutionPayloadBlockHash(t *testing.T) {
	tests := []struct {
		name    string
		payload *api.VersionedExecutionPayload
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixGood",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.ExecutionPayload{
					BlockHash: phase0.Hash32{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					},
				},
			},
			res: phase0.Hash32{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "CapellaNoData",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaGood",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.ExecutionPayload{
					BlockHash: phase0.Hash32{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					},
				},
			},
			res: phase0.Hash32{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "DenebNoData",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebGood",
			payload: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.ExecutionPayload{
					BlockHash: phase0.Hash32{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					},
				},
			},
			res: phase0.Hash32{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.payload.BlockHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedExecutionPayloadTransactions(t *testing.T) {
	tests := []struct {
		name string
		bid  *api.VersionedExecutionPayload
		res  []bellatrix.Transaction
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixGood",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.ExecutionPayload{
					Transactions: []bellatrix.Transaction{
						{0x00},
						{0x01},
					},
				},
			},
			res: []bellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
		{
			name: "CapellaNoData",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaGood",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.ExecutionPayload{
					Transactions: []bellatrix.Transaction{
						{0x00},
						{0x01},
					},
				},
			},
			res: []bellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
		{
			name: "DenebNoData",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebGood",
			bid: &api.VersionedExecutionPayload{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.ExecutionPayload{
					Transactions: []bellatrix.Transaction{
						{0x00},
						{0x01},
					},
				},
			},
			res: []bellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.Transactions()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

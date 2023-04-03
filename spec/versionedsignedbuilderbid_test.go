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

package spec_test

import (
	"testing"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestVersionedSignedBuilderBidEmpty(t *testing.T) {
	empty := &spec.VersionedSignedBuilderBid{
		Version: consensusspec.DataVersionBellatrix,
	}
	require.True(t, empty.IsEmpty())

	mismatch1 := &spec.VersionedSignedBuilderBid{
		Version: consensusspec.DataVersionBellatrix,
		Capella: &capella.SignedBuilderBid{},
	}
	require.True(t, mismatch1.IsEmpty())

	mismatch2 := &spec.VersionedSignedBuilderBid{
		Version:   consensusspec.DataVersionCapella,
		Bellatrix: &bellatrix.SignedBuilderBid{},
	}
	require.True(t, mismatch2.IsEmpty())

	incorrectVersion := &spec.VersionedSignedBuilderBid{
		Version:   consensusspec.DataVersionAltair,
		Bellatrix: &bellatrix.SignedBuilderBid{},
		Capella:   &capella.SignedBuilderBid{},
	}
	require.True(t, incorrectVersion.IsEmpty())

	notEmpty := &spec.VersionedSignedBuilderBid{
		Version:   consensusspec.DataVersionBellatrix,
		Bellatrix: &bellatrix.SignedBuilderBid{},
	}
	require.False(t, notEmpty.IsEmpty())
}

func TestVersionedSignedBuilderBidBuilder(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.BLSPubKey
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Pubkey: phase0.BLSPubKey{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						},
					},
				},
			},
			res: phase0.BLSPubKey{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Pubkey: phase0.BLSPubKey{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						},
					},
				},
			},
			res: phase0.BLSPubKey{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.Builder()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidValue(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  *uint256.Int
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: uint256.NewInt(12345),
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: uint256.NewInt(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.Value()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidParentHash(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.Hash32
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							ParentHash: phase0.Hash32{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
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
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							ParentHash: phase0.Hash32{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
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
			res, err := test.bid.ParentHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidStateRoot(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.Root
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							StateRoot: phase0.Root{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
					},
				},
			},
			res: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							StateRoot: phase0.Root{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
					},
				},
			},
			res: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.StateRoot()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidFeeRecipient(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  consensusbellatrix.ExecutionAddress
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							FeeRecipient: consensusbellatrix.ExecutionAddress{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
							},
						},
					},
				},
			},
			res: consensusbellatrix.ExecutionAddress{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							FeeRecipient: consensusbellatrix.ExecutionAddress{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
							},
						},
					},
				},
			},
			res: consensusbellatrix.ExecutionAddress{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.FeeRecipient()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidTimestamp(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  uint64
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							Timestamp: 12345,
						},
					},
				},
			},
			res: 12345,
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							Timestamp: 12345,
						},
					},
				},
			},
			res: 12345,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.Timestamp()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidTransactionsRoot(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.Root
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							TransactionsRoot: phase0.Root{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
					},
				},
			},
			res: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							TransactionsRoot: phase0.Root{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
					},
				},
			},
			res: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.TransactionsRoot()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidMessageHashTreeRoot(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.Root
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Value:  uint256.NewInt(12345),
						Header: &consensusbellatrix.ExecutionPayloadHeader{},
					},
				},
			},
			res: phase0.Root{
				0x23, 0xef, 0x2a, 0xa3, 0xce, 0x3b, 0x05, 0x76, 0xf6, 0xcb, 0x34, 0x4e, 0xed, 0xa4, 0xdf, 0x63,
				0x9c, 0xd3, 0x88, 0x22, 0x62, 0x86, 0x11, 0x86, 0x5f, 0x74, 0x09, 0x8e, 0x04, 0x94, 0xf8, 0x4b,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Value:  uint256.NewInt(12345),
						Header: &consensuscapella.ExecutionPayloadHeader{},
					},
				},
			},
			res: phase0.Root{
				0x23, 0xef, 0x2a, 0xa3, 0xce, 0x3b, 0x05, 0x76, 0xf6, 0xcb, 0x34, 0x4e, 0xed, 0xa4, 0xdf, 0x63,
				0x9c, 0xd3, 0x88, 0x22, 0x62, 0x86, 0x11, 0x86, 0x5f, 0x74, 0x09, 0x8e, 0x04, 0x94, 0xf8, 0x4b,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.MessageHashTreeRoot()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderBidHeaderHashTreeRoot(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.Root
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Value:  uint256.NewInt(12345),
						Header: &consensusbellatrix.ExecutionPayloadHeader{},
					},
				},
			},
			res: phase0.Root{
				0x22, 0x21, 0x6a, 0x4a, 0x17, 0xe5, 0x5c, 0xc4, 0x1c, 0xe4, 0x54, 0x60, 0x0e, 0x5d, 0xeb, 0x8a,
				0xad, 0x32, 0xf1, 0x55, 0x80, 0xa9, 0x38, 0xb1, 0x91, 0x4f, 0x93, 0xa9, 0x65, 0x2c, 0x0e, 0x2c,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{},
			},
			err: "no data message",
		},
		{
			name: "CapellaNoDataMessageHeader",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{},
				},
			},
			err: "no data message header",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Value:  uint256.NewInt(12345),
						Header: &consensuscapella.ExecutionPayloadHeader{},
					},
				},
			},
			res: phase0.Root{
				0x22, 0x21, 0x6a, 0x4a, 0x17, 0xe5, 0x5c, 0xc4, 0x1c, 0xe4, 0x54, 0x60, 0x0e, 0x5d, 0xeb, 0x8a,
				0xad, 0x32, 0xf1, 0x55, 0x80, 0xa9, 0x38, 0xb1, 0x91, 0x4f, 0x93, 0xa9, 0x65, 0x2c, 0x0e, 0x2c,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.HeaderHashTreeRoot()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderSignature(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  phase0.BLSSignature
		err  string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: phase0.BLSSignature{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			},
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: phase0.BLSSignature{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.bid.Signature()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSignedBuilderString(t *testing.T) {
	tests := []struct {
		name string
		bid  *spec.VersionedSignedBuilderBid
		res  string
	}{
		{
			name: "Empty",
		},
		{
			name: "UnsupportedVersion",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionAltair,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSignedBuilderBid: unsupported data version altair`,
		},
		{
			name: "BellatrixNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSignedBuilderBid: no bellatrix data`,
		},
		{
			name: "BellatrixGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBuilderBid{
					Message: &bellatrix.BuilderBid{
						Header: &consensusbellatrix.ExecutionPayloadHeader{
							ParentHash: phase0.Hash32{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
						Value: uint256.NewInt(12345),
					},
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: `{"version":"bellatrix","data":{"message":{"header":{"parent_hash":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","receipts_root":"0x0000000000000000000000000000000000000000000000000000000000000000","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000","block_number":"0","gas_limit":"0","gas_used":"0","timestamp":"0","extra_data":"0x","base_fee_per_gas":"0","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"value":"12345","pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"signature":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000"}}`,
		},
		{
			name: "CapellaNoData",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSignedBuilderBid: no capella data`,
		},
		{
			name: "CapellaGood",
			bid: &spec.VersionedSignedBuilderBid{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SignedBuilderBid{
					Message: &capella.BuilderBid{
						Header: &consensuscapella.ExecutionPayloadHeader{
							ParentHash: phase0.Hash32{
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
							},
						},
						Value: uint256.NewInt(12345),
					},
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: `{"version":"capella","data":{"message":{"header":{"parent_hash":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","receipts_root":"0x0000000000000000000000000000000000000000000000000000000000000000","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000","block_number":"0","gas_limit":"0","gas_used":"0","timestamp":"0","extra_data":"0x","base_fee_per_gas":"0","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions_root":"0x0000000000000000000000000000000000000000000000000000000000000000","withdrawals_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"value":"12345","pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"signature":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.res, test.bid.String())
		})
	}
}

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
	"github.com/attestantio/go-builder-client/api/deneb"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestVersionedSubmitBlockRequestEmpty(t *testing.T) {
	empty := &spec.VersionedSubmitBlockRequest{
		Version: consensusspec.DataVersionBellatrix,
	}
	require.True(t, empty.IsEmpty())

	mismatch1 := &spec.VersionedSubmitBlockRequest{
		Version: consensusspec.DataVersionBellatrix,
		Capella: &capella.SubmitBlockRequest{},
	}
	require.True(t, mismatch1.IsEmpty())

	mismatch2 := &spec.VersionedSubmitBlockRequest{
		Version:   consensusspec.DataVersionCapella,
		Bellatrix: &bellatrix.SubmitBlockRequest{},
	}
	require.True(t, mismatch2.IsEmpty())

	mismatch3 := &spec.VersionedSubmitBlockRequest{
		Version: consensusspec.DataVersionDeneb,
		Capella: &capella.SubmitBlockRequest{},
	}
	require.True(t, mismatch3.IsEmpty())

	incorrectVersion := &spec.VersionedSubmitBlockRequest{
		Version:   consensusspec.DataVersionAltair,
		Bellatrix: &bellatrix.SubmitBlockRequest{},
		Capella:   &capella.SubmitBlockRequest{},
	}
	require.True(t, incorrectVersion.IsEmpty())

	notEmpty := &spec.VersionedSubmitBlockRequest{
		Version:   consensusspec.DataVersionBellatrix,
		Bellatrix: &bellatrix.SubmitBlockRequest{},
	}
	require.False(t, notEmpty.IsEmpty())
}

func TestVersionedSubmitBlockRequestSlot(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     uint64
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot: 12345,
					},
				},
			},
			res: 12345,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot: 12345,
					},
				},
			},
			res: 12345,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot: 12345,
					},
				},
			},
			res: 12345,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.Slot()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestBlockHash(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			res, err := test.request.BlockHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestBuilder(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.BLSPubKey
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BuilderPubkey: phase0.BLSPubKey{
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BuilderPubkey: phase0.BLSPubKey{
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						BuilderPubkey: phase0.BLSPubKey{
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
			res, err := test.request.Builder()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestProposerFeeRecipient(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     consensusbellatrix.ExecutionAddress
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerFeeRecipient: consensusbellatrix.ExecutionAddress{
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
						},
					},
				},
			},
			res: consensusbellatrix.ExecutionAddress{
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
			},
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerFeeRecipient: consensusbellatrix.ExecutionAddress{
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
						},
					},
				},
			},
			res: consensusbellatrix.ExecutionAddress{
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
			},
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerFeeRecipient: consensusbellatrix.ExecutionAddress{
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
							0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
						},
					},
				},
			},
			res: consensusbellatrix.ExecutionAddress{
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
				0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.ProposerFeeRecipient()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestProposerPubKey(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.BLSPubKey
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerPubkey: phase0.BLSPubKey{
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerPubkey: phase0.BLSPubKey{
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ProposerPubkey: phase0.BLSPubKey{
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
			res, err := test.request.ProposerPubKey()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestParentHash(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			res, err := test.request.ParentHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestValue(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     *uint256.Int
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: uint256.NewInt(12345),
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: uint256.NewInt(12345),
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: uint256.NewInt(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.Value()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestBidTrace(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     *v1.BidTrace
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: &v1.BidTrace{
				Slot:  123,
				Value: uint256.NewInt(12345),
			},
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: &v1.BidTrace{
				Slot:  123,
				Value: uint256.NewInt(12345),
			},
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataMessage",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data message",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
				},
			},
			res: &v1.BidTrace{
				Slot:  123,
				Value: uint256.NewInt(12345),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.BidTrace()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestSignature(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.BLSSignature
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
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
			res, err := test.request.Signature()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestExecutionPayloadBlockHash(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						BlockHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			res, err := test.request.ExecutionPayloadBlockHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestExecutionPayloadParentHash(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			res, err := test.request.ExecutionPayloadParentHash()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestPrevRandao(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     phase0.Hash32
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						PrevRandao: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						PrevRandao: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						PrevRandao: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
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
			res, err := test.request.PrevRandao()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestGasLimit(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     uint64
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						GasLimit: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						GasLimit: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						GasLimit: 123,
					},
				},
			},
			res: 123,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.GasLimit()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestGasUsed(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     uint64
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						GasUsed: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						GasUsed: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						GasUsed: 123,
					},
				},
			},
			res: 123,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.GasUsed()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestBlockNumber(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     uint64
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						BlockNumber: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						BlockNumber: 123,
					},
				},
			},
			res: 123,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						BlockNumber: 123,
					},
				},
			},
			res: 123,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.BlockNumber()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     uint64
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						Timestamp: 12345,
					},
				},
			},
			res: 12345,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						Timestamp: 12345,
					},
				},
			},
			res: 12345,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						Timestamp: 12345,
					},
				},
			},
			res: 12345,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.Timestamp()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestTransactions(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     []consensusbellatrix.Transaction
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			err: "unsupported version",
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "no data",
		},
		{
			name: "BellatrixNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version:   consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						Transactions: []consensusbellatrix.Transaction{
							{0x00},
							{0x01},
						},
					},
				},
			},
			res: []consensusbellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						Transactions: []consensusbellatrix.Transaction{
							{0x00},
							{0x01},
						},
					},
				},
			},
			res: []consensusbellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						Transactions: []consensusbellatrix.Transaction{
							{0x00},
							{0x01},
						},
					},
				},
			},
			res: []consensusbellatrix.Transaction{
				{0x00},
				{0x01},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.Transactions()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestWithdrawals(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     []*consensuscapella.Withdrawal
		err     string
	}{
		{
			name: "Empty",
			err:  "nil struct",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			err: "unsupported version",
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			err: "no data",
		},
		{
			name: "CapellaNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						Withdrawals: []*consensuscapella.Withdrawal{
							{
								Index:          5,
								ValidatorIndex: 10,
								Address:        consensusbellatrix.ExecutionAddress{},
								Amount:         12345,
							},
							{
								Index:          10,
								ValidatorIndex: 20,
								Address:        consensusbellatrix.ExecutionAddress{},
								Amount:         12345,
							},
						},
					},
				},
			},
			res: []*consensuscapella.Withdrawal{
				{
					Index:          5,
					ValidatorIndex: 10,
					Address:        consensusbellatrix.ExecutionAddress{},
					Amount:         12345,
				},
				{
					Index:          10,
					ValidatorIndex: 20,
					Address:        consensusbellatrix.ExecutionAddress{},
					Amount:         12345,
				},
			},
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			err: "no data",
		},
		{
			name: "DenebNoDataExecutionPayload",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb:   &deneb.SubmitBlockRequest{},
			},
			err: "no data execution payload",
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						Withdrawals: []*consensuscapella.Withdrawal{
							{
								Index:          5,
								ValidatorIndex: 10,
								Address:        consensusbellatrix.ExecutionAddress{},
								Amount:         12345,
							},
							{
								Index:          10,
								ValidatorIndex: 20,
								Address:        consensusbellatrix.ExecutionAddress{},
								Amount:         12345,
							},
						},
					},
				},
			},
			res: []*consensuscapella.Withdrawal{
				{
					Index:          5,
					ValidatorIndex: 10,
					Address:        consensusbellatrix.ExecutionAddress{},
					Amount:         12345,
				},
				{
					Index:          10,
					ValidatorIndex: 20,
					Address:        consensusbellatrix.ExecutionAddress{},
					Amount:         12345,
				},
			},
		},						
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.request.Withdrawals()
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}

func TestVersionedSubmitBlockRequestString(t *testing.T) {
	tests := []struct {
		name    string
		request *spec.VersionedSubmitBlockRequest
		res     string
	}{
		{
			name: "Empty",
		},
		{
			name: "UnsupportedVersion",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionAltair,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSubmitBlockRequest: unsupported data version altair`,
		},
		{
			name: "BellatrixNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSubmitBlockRequest: no bellatrix data`,
		},
		{
			name: "BellatrixGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
					ExecutionPayload: &consensusbellatrix.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						},
					},
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: `{"version":"bellatrix","data":{"message":{"slot":"123","parent_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","builder_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_fee_recipient":"0x0000000000000000000000000000000000000000","gas_limit":"0","gas_used":"0","value":"12345"},"execution_payload":{"parent_hash":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","receipts_root":"0x0000000000000000000000000000000000000000000000000000000000000000","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000","block_number":"0","gas_limit":"0","gas_used":"0","timestamp":"0","extra_data":"0x","base_fee_per_gas":"0","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions":[]},"signature":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000"}}`,
		},
		{
			name: "CapellaNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSubmitBlockRequest: no capella data`,
		},
		{
			name: "CapellaGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionCapella,
				Capella: &capella.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
					ExecutionPayload: &consensuscapella.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						},
						Withdrawals: make([]*consensuscapella.Withdrawal, 0),
					},
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: `{"version":"capella","data":{"message":{"slot":"123","parent_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","builder_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_fee_recipient":"0x0000000000000000000000000000000000000000","gas_limit":"0","gas_used":"0","value":"12345"},"execution_payload":{"parent_hash":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","receipts_root":"0x0000000000000000000000000000000000000000000000000000000000000000","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000","block_number":"0","gas_limit":"0","gas_used":"0","timestamp":"0","extra_data":"0x","base_fee_per_gas":"0","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions":[],"withdrawals":[]},"signature":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000"}}`,
		},
		{
			name: "DenebNoData",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
			},
			res: `ERR: json: error calling MarshalJSON for type *spec.VersionedSubmitBlockRequest: no deneb data`,
		},
		{
			name: "DenebGood",
			request: &spec.VersionedSubmitBlockRequest{
				Version: consensusspec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message: &v1.BidTrace{
						Slot:  123,
						Value: uint256.NewInt(12345),
					},
					ExecutionPayload: &consensusdeneb.ExecutionPayload{
						ParentHash: phase0.Hash32{
							0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						},
						BaseFeePerGas: uint256.NewInt(0),
						Withdrawals: make([]*consensuscapella.Withdrawal, 0),
					},
					BlobsBundle: &deneb.BlobsBundle{
						Commitments: make([]consensusdeneb.KzgCommitment, 0),
						Proofs: 	make([]consensusdeneb.KzgProof, 0),
						Blobs: 		make([]consensusdeneb.Blob, 0),
					},
					Signature: phase0.BLSSignature{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
			},
			res: `{"version":"deneb","data":{"message":{"slot":"123","parent_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","builder_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","proposer_fee_recipient":"0x0000000000000000000000000000000000000000","gas_limit":"0","gas_used":"0","value":"12345"},"execution_payload":{"parent_hash":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","fee_recipient":"0x0000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","receipts_root":"0x0000000000000000000000000000000000000000000000000000000000000000","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000","block_number":"0","gas_limit":"0","gas_used":"0","timestamp":"0","extra_data":"0x","base_fee_per_gas":"0","block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions":[],"withdrawals":[],"data_gas_used":"0","excess_data_gas":"0"},"blobs_bundle":{"commitments":[],"proofs":[],"blobs":[]},"signature":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.res, test.request.String())
		})
	}
}

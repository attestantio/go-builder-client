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

package bellatrix_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// sszType is implemented by every generated SSZ codec in this package.
type sszType interface {
	MarshalSSZ() ([]byte, error)
	UnmarshalSSZ([]byte) error
	HashTreeRoot() ([32]byte, error)
}

// assertSSZGolden verifies, for a constructed object:
//  1. the encoded size matches the pinned value,
//  2. the SHA-256 of the encoding matches the pinned value (a compact stand-in for
//     pinning the full hex, which would be hundreds of KB for blob-bearing types),
//  3. decode→re-encode reproduces the original bytes (round-trip stability), and
//  4. the hash tree root matches the pinned value.
//
// The pinned values are regression baselines generated from the current dynssz
// output; a future regeneration or dependency bump that changes MarshalSSZ or
// HashTreeRoot will fail these assertions.
func assertSSZGolden(t *testing.T, obj sszType, fresh sszType, wantSize int, wantSHA, wantRoot string) {
	t.Helper()

	enc, err := obj.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, wantSize, len(enc), "encoded size")

	sum := sha256.Sum256(enc)
	require.Equal(t, wantSHA, hex.EncodeToString(sum[:]), "sha256 of encoding")

	require.NoError(t, fresh.UnmarshalSSZ(enc))
	reenc, err := fresh.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, enc, reenc, "round-trip encoding")

	root, err := obj.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, wantRoot, hex.EncodeToString(root[:]), "hash tree root")
}

func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

func hash32(v byte) phase0.Hash32 { var h phase0.Hash32; fill(h[:], v); return h }
func root32(v byte) phase0.Root   { var r phase0.Root; fill(r[:], v); return r }
func b32(v byte) [32]byte         { var r [32]byte; fill(r[:], v); return r }
func bloom(v byte) [256]byte      { var r [256]byte; fill(r[:], v); return r }

func addr(v byte) consensusbellatrix.ExecutionAddress {
	var a consensusbellatrix.ExecutionAddress
	fill(a[:], v)

	return a
}
func pubkey(v byte) phase0.BLSPubKey { var p phase0.BLSPubKey; fill(p[:], v); return p }
func sig(v byte) phase0.BLSSignature { var s phase0.BLSSignature; fill(s[:], v); return s }

func bidTrace() *apiv1.BidTrace {
	return &apiv1.BidTrace{
		Slot:                 12345,
		ParentHash:           hash32(0x11),
		BlockHash:            hash32(0x22),
		BuilderPubkey:        pubkey(0x33),
		ProposerPubkey:       pubkey(0x44),
		ProposerFeeRecipient: addr(0x55),
		GasLimit:             30000000,
		GasUsed:              21000,
		Value:                uint256.NewInt(123456789),
	}
}

func executionPayloadHeader() *consensusbellatrix.ExecutionPayloadHeader {
	return &consensusbellatrix.ExecutionPayloadHeader{
		ParentHash:       hash32(0x01),
		FeeRecipient:     addr(0x02),
		StateRoot:        b32(0x03),
		ReceiptsRoot:     b32(0x04),
		LogsBloom:        bloom(0x05),
		PrevRandao:       b32(0x06),
		BlockNumber:      100,
		GasLimit:         30000000,
		GasUsed:          21000,
		Timestamp:        1700000000,
		ExtraData:        []byte{0xca, 0xfe},
		BaseFeePerGas:    b32(0x07),
		BlockHash:        hash32(0x08),
		TransactionsRoot: root32(0x09),
	}
}

func executionPayload() *consensusbellatrix.ExecutionPayload {
	return &consensusbellatrix.ExecutionPayload{
		ParentHash:    hash32(0x01),
		FeeRecipient:  addr(0x02),
		StateRoot:     b32(0x03),
		ReceiptsRoot:  b32(0x04),
		LogsBloom:     bloom(0x05),
		PrevRandao:    b32(0x06),
		BlockNumber:   100,
		GasLimit:      30000000,
		GasUsed:       21000,
		Timestamp:     1700000000,
		ExtraData:     []byte{0xca, 0xfe},
		BaseFeePerGas: b32(0x07),
		BlockHash:     hash32(0x08),
		Transactions:  []consensusbellatrix.Transaction{{0xde, 0xad, 0xbe, 0xef}},
	}
}

func builderBid() *bellatrix.BuilderBid {
	return &bellatrix.BuilderBid{
		Header: executionPayloadHeader(),
		Value:  uint256.NewInt(987654321),
		Pubkey: pubkey(0x77),
	}
}

func TestBuilderBidGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, builderBid(), new(bellatrix.BuilderBid),
		622,
		"a79ad6a5c16e954107649807951eda3c6ec95cd5e2b762a6ec54006bfec77dea",
		"7ce903b53b30ba89b6043acb579b6aeb827a9706f028482e6bbb802ce9387a1b",
	)
}

func TestSignedBuilderBidGoldenSSZ(t *testing.T) {
	obj := &bellatrix.SignedBuilderBid{Message: builderBid(), Signature: sig(0x88)}
	assertSSZGolden(t, obj, new(bellatrix.SignedBuilderBid),
		722,
		"8cc73a68a08077d52e11d33b07c2e42a0c9927df57ee0f6b7127da108ee2e06a",
		"5759170bca7b4e7cfc5b6e1b97ac0bfb151af617224b3f17ed7a4d056d1e9300",
	)
}

func TestSubmitBlockRequestGoldenSSZ(t *testing.T) {
	obj := &bellatrix.SubmitBlockRequest{Message: bidTrace(), ExecutionPayload: executionPayload(), Signature: sig(0x99)}
	assertSSZGolden(t, obj, new(bellatrix.SubmitBlockRequest),
		854,
		"c48671259e02f350d30f9a0913b2f73f1513026289829ed272e933da8b03470e",
		"9ae000836655d9ce65abba4eb9a145d7708eb0423dc6f6743e9b22245383d13b",
	)
}

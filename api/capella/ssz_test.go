// Copyright © 2025 Attestant Limited.
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

package capella_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
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

// assertSSZGolden verifies size, a SHA-256 of the encoding (a compact stand-in for
// the full hex), decode→re-encode round-trip stability, and the hash tree root
// against pinned regression baselines generated from the current dynssz output.
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

func withdrawals() []*consensuscapella.Withdrawal {
	return []*consensuscapella.Withdrawal{
		{Index: 1, ValidatorIndex: 2, Address: addr(0x0a), Amount: 32000000000},
	}
}

func executionPayloadHeader() *consensuscapella.ExecutionPayloadHeader {
	return &consensuscapella.ExecutionPayloadHeader{
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
		WithdrawalsRoot:  root32(0x0a),
	}
}

func executionPayload() *consensuscapella.ExecutionPayload {
	return &consensuscapella.ExecutionPayload{
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
		Withdrawals:   withdrawals(),
	}
}

func builderBid() *capella.BuilderBid {
	return &capella.BuilderBid{
		Header: executionPayloadHeader(),
		Value:  uint256.NewInt(987654321),
		Pubkey: pubkey(0x77),
	}
}

func TestSignedBuilderBidGoldenSSZ(t *testing.T) {
	obj := &capella.SignedBuilderBid{Message: builderBid(), Signature: sig(0x88)}
	assertSSZGolden(t, obj, new(capella.SignedBuilderBid),
		754,
		"50e7b9dd4a3b9aefbfd429f3b059fae9c25240de8de1a5ac4201e1b79b1dbc75",
		"95a8a52d834894972757d9ac0d66e48994c3aa3fb57d08949b741784fe830bbd",
	)
}

func TestSubmitBlockRequestGoldenSSZ(t *testing.T) {
	obj := &capella.SubmitBlockRequest{Message: bidTrace(), ExecutionPayload: executionPayload(), Signature: sig(0x99)}
	assertSSZGolden(t, obj, new(capella.SubmitBlockRequest),
		902,
		"73e1f0f4e279d6d086a217c9a8c3234811bcead9ce956b66575e14c520c3b60b",
		"e61cb78128a8f4953da5fd38eee4c30ba49d4499b5d7e1fd8529007b10ed2630",
	)
}

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

package deneb_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-builder-client/api/deneb"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
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
// the full hex, which is hundreds of KB for blob-bearing types), decode→re-encode
// round-trip stability, and the hash tree root against pinned regression baselines
// generated from the current dynssz output.
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

func commitment(v byte) consensusdeneb.KZGCommitment {
	var c consensusdeneb.KZGCommitment
	fill(c[:], v)

	return c
}

func proof(v byte) consensusdeneb.KZGProof {
	var p consensusdeneb.KZGProof
	fill(p[:], v)

	return p
}

func blob(v byte) consensusdeneb.Blob {
	var b consensusdeneb.Blob
	fill(b[:], v)

	return b
}

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

func executionPayloadHeader() *consensusdeneb.ExecutionPayloadHeader {
	return &consensusdeneb.ExecutionPayloadHeader{
		ParentHash:       hash32(0x01),
		FeeRecipient:     addr(0x02),
		StateRoot:        root32(0x03),
		ReceiptsRoot:     root32(0x04),
		LogsBloom:        bloom(0x05),
		PrevRandao:       b32(0x06),
		BlockNumber:      100,
		GasLimit:         30000000,
		GasUsed:          21000,
		Timestamp:        1700000000,
		ExtraData:        []byte{0xca, 0xfe},
		BaseFeePerGas:    uint256.NewInt(1000000000),
		BlockHash:        hash32(0x08),
		TransactionsRoot: root32(0x09),
		WithdrawalsRoot:  root32(0x0a),
		BlobGasUsed:      131072,
		ExcessBlobGas:    0,
	}
}

func executionPayload() *consensusdeneb.ExecutionPayload {
	return &consensusdeneb.ExecutionPayload{
		ParentHash:    hash32(0x01),
		FeeRecipient:  addr(0x02),
		StateRoot:     root32(0x03),
		ReceiptsRoot:  root32(0x04),
		LogsBloom:     bloom(0x05),
		PrevRandao:    b32(0x06),
		BlockNumber:   100,
		GasLimit:      30000000,
		GasUsed:       21000,
		Timestamp:     1700000000,
		ExtraData:     []byte{0xca, 0xfe},
		BaseFeePerGas: uint256.NewInt(1000000000),
		BlockHash:     hash32(0x08),
		Transactions:  []consensusbellatrix.Transaction{{0xde, 0xad, 0xbe, 0xef}},
		Withdrawals:   withdrawals(),
		BlobGasUsed:   131072,
		ExcessBlobGas: 0,
	}
}

func blobsBundle() *deneb.BlobsBundle {
	return &deneb.BlobsBundle{
		Commitments: []consensusdeneb.KZGCommitment{commitment(0xaa)},
		Proofs:      []consensusdeneb.KZGProof{proof(0xbb)},
		Blobs:       []consensusdeneb.Blob{blob(0xcc)},
	}
}

func builderBid() *deneb.BuilderBid {
	return &deneb.BuilderBid{
		Header:             executionPayloadHeader(),
		BlobKZGCommitments: []consensusdeneb.KZGCommitment{commitment(0xaa)},
		Value:              uint256.NewInt(987654321),
		Pubkey:             pubkey(0x77),
	}
}

func TestBuilderBidGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, builderBid(), new(deneb.BuilderBid),
		722,
		"099129c6b5a805d6bbc75a03fc1f27d286e1e0b8273ecb47e62e329986a31fd9",
		"ee0997b0dc62a5af0082591e930cc78ab7830e8d21baaa6349db15e3a3ec7cac",
	)
}

func TestSignedBuilderBidGoldenSSZ(t *testing.T) {
	obj := &deneb.SignedBuilderBid{Message: builderBid(), Signature: sig(0x88)}
	assertSSZGolden(t, obj, new(deneb.SignedBuilderBid),
		822,
		"045da7d9d06fc7003c8d116bafbe7b6ce6eb16eb04efd8fd42bbb7128837de8d",
		"b2263b691742dd7d8776d4e9eefba09964222c5b71112cb525353f82a981ecad",
	)
}

func TestSubmitBlockRequestGoldenSSZ(t *testing.T) {
	obj := &deneb.SubmitBlockRequest{
		Message:          bidTrace(),
		ExecutionPayload: executionPayload(),
		BlobsBundle:      blobsBundle(),
		Signature:        sig(0x99),
	}
	assertSSZGolden(t, obj, new(deneb.SubmitBlockRequest),
		132102,
		"472b06e20c0c82ba2894156bb2d9cd31aab39850aa17fa67ac163848db9b2d1f",
		"c44feff7c9b25e3bcda566efbb724067bb65075c4ef850053a36bf7d2618c9e4",
	)
}

func TestBlobsBundleGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, blobsBundle(), new(deneb.BlobsBundle),
		131180,
		"3227d9a98f3f490f3f827a404ed7330328c90344811dc15674983fea38cf9281",
		"a05a51f3b1cfa80084d20cf159969b6baf12db94836ac91b0bf6084bdadf77c3",
	)
}

func TestExecutionPayloadAndBlobsBundleGoldenSSZ(t *testing.T) {
	obj := &deneb.ExecutionPayloadAndBlobsBundle{ExecutionPayload: executionPayload(), BlobsBundle: blobsBundle()}
	assertSSZGolden(t, obj, new(deneb.ExecutionPayloadAndBlobsBundle),
		131770,
		"310240e49c096ebdb97a4fe269a3fd6cb2c9613b387822cd3db5d39356ad6ca0",
		"3c3c593ca0e4519fd33997b4ed6358d880a2d7f0a278cf343eaec277f07de523",
	)
}

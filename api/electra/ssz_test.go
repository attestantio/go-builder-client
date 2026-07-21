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

package electra_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	consensuselectra "github.com/attestantio/go-eth2-client/spec/electra"
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

func executionRequests() *consensuselectra.ExecutionRequests {
	wc := b32(0xd2)

	return &consensuselectra.ExecutionRequests{
		Deposits: []*consensuselectra.DepositRequest{
			{Pubkey: pubkey(0xd1), WithdrawalCredentials: wc[:], Amount: 32000000000, Signature: sig(0xd3), Index: 7},
		},
		Withdrawals: []*consensuselectra.WithdrawalRequest{
			{SourceAddress: addr(0xe1), ValidatorPubkey: pubkey(0xe2), Amount: 100},
		},
		Consolidations: []*consensuselectra.ConsolidationRequest{
			{SourceAddress: addr(0xf1), SourcePubkey: pubkey(0xf2), TargetPubkey: pubkey(0xf3)},
		},
	}
}

func builderBid() *electra.BuilderBid {
	return &electra.BuilderBid{
		Header:             executionPayloadHeader(),
		BlobKZGCommitments: []consensusdeneb.KZGCommitment{commitment(0xaa)},
		ExecutionRequests:  executionRequests(),
		Value:              uint256.NewInt(987654321),
		Pubkey:             pubkey(0x77),
	}
}

func TestBuilderBidGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, builderBid(), new(electra.BuilderBid),
		1122,
		"566695298114f4adc863d4d4bf52d5c6ed54aa1efab6b4d4e40a1e1019b723de",
		"b0f575726ade5962fa2b527ab1ea2e380db62d61f42b185fd215e4357f06759e",
	)
}

func TestSignedBuilderBidGoldenSSZ(t *testing.T) {
	obj := &electra.SignedBuilderBid{Message: builderBid(), Signature: sig(0x88)}
	assertSSZGolden(t, obj, new(electra.SignedBuilderBid),
		1222,
		"c9ef547efa5517fe0170ddac5346fd7fb254583fc4562650dfc97c853aae86f6",
		"d7504bd11cb27a44b9f7e99331dda8223732c56546d1a08fca892eb922b6c1d5",
	)
}

func TestSubmitBlockRequestGoldenSSZ(t *testing.T) {
	obj := &electra.SubmitBlockRequest{
		Message:           bidTrace(),
		ExecutionPayload:  executionPayload(),
		BlobsBundle:       blobsBundle(),
		ExecutionRequests: executionRequests(),
		Signature:         sig(0x99),
	}
	assertSSZGolden(t, obj, new(electra.SubmitBlockRequest),
		132502,
		"118d0aab2276374ae0d8f081c5a30db55d20e5e2cf67d2c6464465ec2de3589f",
		"a6939ba61dc8b3960fbd14060d9ef352783390a56bf2a82ea0eb11ccb7968751",
	)
}

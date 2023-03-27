package v2

import (
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SubmitBlockRequest is the request from the builder to submit a block.
type SubmitBlockRequest struct {
	Message                *v1.BidTrace
	ExecutionPayloadHeader *capella.ExecutionPayloadHeader
	Transactions           []bellatrix.Transaction
	Withdrawals            []capella.Withdrawal
	Signature              phase0.BLSSignature `ssz-size:"96"`
}

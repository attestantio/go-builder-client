package v2

import (
	"encoding/json"
	"fmt"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SubmitBlockRequest is the v2 request from the builder to submit a block.
// TODO(JWT): why is this still using the Capella header?
type SubmitBlockRequest struct {
	Message                *v1.BidTrace
	ExecutionPayloadHeader *capella.ExecutionPayloadHeader
	Signature              phase0.BLSSignature `ssz-size:"96"`
	Transactions           []bellatrix.Transaction
	Withdrawals            []*capella.Withdrawal
}

// String returns a string version of the structure.
func (s *SubmitBlockRequest) String() string {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

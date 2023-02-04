package capella

import (
	"fmt"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
)

// SubmitBlockRequest is the request from the builder to submit a block.
type SubmitBlockRequest struct {
	Message          *v1.BidTrace
	ExecutionPayload *capella.ExecutionPayload
	Signature        phase0.BLSSignature `ssz-size:"96"`
}

// String returns a string version of the structure.
func (s *SubmitBlockRequest) String() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return string(data)
}

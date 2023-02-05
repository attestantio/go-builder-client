package capella

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// submitBlockRequestJSON is the spec representation of the struct.
type submitBlockRequestJSON struct {
	Message          *v1.BidTrace              `json:"message"`
	ExecutionPayload *capella.ExecutionPayload `json:"execution_payload"`
	Signature        string                    `json:"signature"`
}

// MarshalJSON implements json.Marshaler.
func (s *SubmitBlockRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(&submitBlockRequestJSON{
		Signature:        fmt.Sprintf("%#x", s.Signature),
		Message:          s.Message,
		ExecutionPayload: s.ExecutionPayload,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var data submitBlockRequestJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	return s.unpack(&data)
}

func (s *SubmitBlockRequest) unpack(data *submitBlockRequestJSON) error {
	if data.Message == nil {
		return errors.New("message missing")
	}
	s.Message = data.Message

	if data.Signature == "" {
		return errors.New("signature missing")
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(data.Signature, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid signature")
	}
	if len(signature) != phase0.SignatureLength {
		return errors.New("incorrect length for signature")
	}
	copy(s.Signature[:], signature)

	if data.ExecutionPayload == nil {
		return errors.New("execution payload missing")
	}
	s.ExecutionPayload = data.ExecutionPayload
	return nil
}

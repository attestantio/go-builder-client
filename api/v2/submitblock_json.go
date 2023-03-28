package v2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// submitBlockRequestJSON is the spec representation of the struct.
type submitBlockRequestJSON struct {
	Message                *v1.BidTrace                    `json:"message"`
	ExecutionPayloadHeader *capella.ExecutionPayloadHeader `json:"execution_payload_header"`
	Signature              string                          `json:"signature"`
	Transactions           []string                        `json:"transactions"`
	Withdrawals            []*capella.Withdrawal           `json:"withdrawals"`
}

// MarshalJSON implements json.Marshaler.
func (s *SubmitBlockRequest) MarshalJSON() ([]byte, error) {
	transactions := make([]string, len(s.Transactions))
	for i := range s.Transactions {
		transactions[i] = fmt.Sprintf("%#x", s.Transactions[i])
	}
	return json.Marshal(&submitBlockRequestJSON{
		Message:                s.Message,
		ExecutionPayloadHeader: s.ExecutionPayloadHeader,
		Signature:              fmt.Sprintf("%#x", s.Signature),
		Transactions:           transactions,
		Withdrawals:            s.Withdrawals,
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
	// field: Message
	if data.Message == nil {
		return errors.New("message missing")
	}
	s.Message = data.Message

	// field: ExecutionPayloadHeader
	if data.ExecutionPayloadHeader == nil {
		return errors.New("execution payload header missing")
	}
	s.ExecutionPayloadHeader = data.ExecutionPayloadHeader

	// field: Signature
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

	// field: Transactions
	if data.Transactions == nil {
		return errors.New("transactions missing")
	}
	transactions := make([]bellatrix.Transaction, len(data.Transactions))
	for i := range data.Transactions {
		if data.Transactions[i] == "" {
			return errors.New("transaction missing")
		}
		tmp, err := hex.DecodeString(strings.TrimPrefix(data.Transactions[i], "0x"))
		if err != nil {
			return errors.Wrap(err, "invalid value for transaction")
		}
		transactions[i] = bellatrix.Transaction(tmp)
	}
	s.Transactions = transactions

	// field: Withdrawals
	if data.Withdrawals == nil {
		return errors.New("withdrawals missing")
	}
	s.Withdrawals = data.Withdrawals

	return nil
}

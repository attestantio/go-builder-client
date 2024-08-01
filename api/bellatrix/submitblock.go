package bellatrix

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// SubmitBlockRequest is the request from the builder to submit a block.
type SubmitBlockRequest struct {
	Message          *apiv1.BidTrace
	ExecutionPayload *bellatrix.ExecutionPayload
	Signature        phase0.BLSSignature `ssz-size:"96"`
}

// submitBlockRequestJSON is the spec representation of the struct.
type submitBlockRequestJSON struct {
	Message          *apiv1.BidTrace             `json:"message"`
	ExecutionPayload *bellatrix.ExecutionPayload `json:"execution_payload"`
	Signature        string                      `json:"signature"`
}

// submitBlockRequestYAML is the spec representation of the struct.
type submitBlockRequestYAML struct {
	Message          *apiv1.BidTrace             `yaml:"message"`
	ExecutionPayload *bellatrix.ExecutionPayload `yaml:"execution_payload"`
	Signature        string                      `yaml:"signature"`
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

// MarshalYAML implements yaml.Marshaler.
func (s *SubmitBlockRequest) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&submitBlockRequestYAML{
		Message:          s.Message,
		Signature:        fmt.Sprintf("%#x", s.Signature),
		ExecutionPayload: s.ExecutionPayload,
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SubmitBlockRequest) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data submitBlockRequestJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return s.unpack(&data)
}

// String returns a string version of the structure.
func (s *SubmitBlockRequest) String() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

package capella

import (
	"bytes"
	"fmt"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/goccy/go-yaml"
)

// submitBlockRequestYAML is the spec representation of the struct.
type submitBlockRequestYAML struct {
	Message          *v1.BidTrace              `yaml:"message"`
	ExecutionPayload *capella.ExecutionPayload `yaml:"execution_payload"`
	Signature        string                    `yaml:"signature"`
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

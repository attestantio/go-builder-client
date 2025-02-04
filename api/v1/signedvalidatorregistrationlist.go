package v1

import (
	"encoding/json"
	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// SignedValidatorRegistrationList represents a list of SignedValidatorRegistration.
type SignedValidatorRegistrationList struct {
	Items []*SignedValidatorRegistration `ssz-max:"1099511627776" json:"items" yaml:"items"`
}

// MarshalJSON implements json.Marshaler.
func (s *SignedValidatorRegistrationList) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Items)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SignedValidatorRegistrationList) UnmarshalJSON(input []byte) error {
	var data []*SignedValidatorRegistration
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	s.Items = data
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s *SignedValidatorRegistrationList) MarshalYAML() ([]byte, error) {
	return yaml.Marshal(s.Items)
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SignedValidatorRegistrationList) UnmarshalYAML(input []byte) error {
	var data []*SignedValidatorRegistration
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}
	s.Items = data
	return nil
}

// String returns a YAML representation of the list.
func (s *SignedValidatorRegistrationList) String() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return "ERR: " + err.Error()
	}
	return string(data)
}

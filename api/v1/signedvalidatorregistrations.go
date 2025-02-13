package v1

import (
	"encoding/json"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

// SignedValidatorRegistrations represents a list of SignedValidatorRegistration.
type SignedValidatorRegistrations struct {
	Registrations []*SignedValidatorRegistration `json:"registrations" ssz-max:"1099511627776" yaml:"registrations"`
}

// MarshalJSON implements json.Marshaler.
func (s *SignedValidatorRegistrations) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Registrations)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SignedValidatorRegistrations) UnmarshalJSON(input []byte) error {
	var data []*SignedValidatorRegistration
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	s.Registrations = data

	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s *SignedValidatorRegistrations) MarshalYAML() ([]byte, error) {
	return yaml.Marshal(s.Registrations)
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *SignedValidatorRegistrations) UnmarshalYAML(input []byte) error {
	var data []*SignedValidatorRegistration
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}
	s.Registrations = data

	return nil
}

// String returns a YAML representation of the list.
func (s *SignedValidatorRegistrations) String() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

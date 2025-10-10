// Copyright © 2022 Attestant Limited.
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

package deneb

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// signedBuilderBidJSON is the spec representation of the struct.
type signedBuilderBidJSON struct {
	Message   *BuilderBid `json:"message"`
	Signature string      `json:"signature"`
}

// MarshalJSON implements json.Marshaler.
func (s *SignedBuilderBid) MarshalJSON() ([]byte, error) {
	return json.Marshal(&signedBuilderBidJSON{
		Message:   s.Message,
		Signature: fmt.Sprintf("%#x", s.Signature),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *SignedBuilderBid) UnmarshalJSON(input []byte) error {
	var data signedBuilderBidJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return s.unpack(&data)
}

func (s *SignedBuilderBid) unpack(data *signedBuilderBidJSON) error {
	if data.Message == nil {
		return errors.New("message missing")
	}

	s.Message = data.Message
	if data.Signature == "" {
		return errors.New("signature missing")
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(data.Signature, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for signature")
	}

	if len(signature) != phase0.SignatureLength {
		return errors.New("incorrect length for signature")
	}

	copy(s.Signature[:], signature)

	return nil
}

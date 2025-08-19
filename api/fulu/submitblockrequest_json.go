// Copyright © 2025 Attestant Limited.
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

package fulu

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	apideneb "github.com/attestantio/go-builder-client/api/deneb"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// submitBlockRequestJSON is the spec representation of the struct.
type submitBlockRequestJSON struct {
	Message           *apiv1.BidTrace            `json:"message"`
	ExecutionPayload  *deneb.ExecutionPayload    `json:"execution_payload"`
	BlobsBundle       *apideneb.BlobsBundle      `json:"blobs_bundle"`
	ExecutionRequests *electra.ExecutionRequests `json:"execution_requests"`
	Signature         string                     `json:"signature"`
}

// MarshalJSON implements json.Marshaler.
func (s *SubmitBlockRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(&submitBlockRequestJSON{
		Message:           s.Message,
		ExecutionPayload:  s.ExecutionPayload,
		BlobsBundle:       s.BlobsBundle,
		ExecutionRequests: s.ExecutionRequests,
		Signature:         fmt.Sprintf("%#x", s.Signature),
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

	if data.BlobsBundle == nil {
		return errors.New("blobs bundle missing")
	}
	s.BlobsBundle = data.BlobsBundle

	if data.ExecutionRequests == nil {
		return errors.New("execution requests missing")
	}
	s.ExecutionRequests = data.ExecutionRequests

	return nil
}

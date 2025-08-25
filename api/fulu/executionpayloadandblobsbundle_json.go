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
	"encoding/json"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/pkg/errors"
)

// executionPayloadAndBlobsBundleJSON is the spec representation of the struct.
type executionPayloadAndBlobsBundleJSON struct {
	ExecutionPayload *deneb.ExecutionPayload `json:"execution_payload"`
	BlobsBundle      *BlobsBundle            `json:"blobs_bundle"`
}

// MarshalJSON implements json.Marshaler.
func (e *ExecutionPayloadAndBlobsBundle) MarshalJSON() ([]byte, error) {
	return json.Marshal(&executionPayloadAndBlobsBundleJSON{
		ExecutionPayload: e.ExecutionPayload,
		BlobsBundle:      e.BlobsBundle,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *ExecutionPayloadAndBlobsBundle) UnmarshalJSON(input []byte) error {
	var data executionPayloadAndBlobsBundleJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return e.unpack(&data)
}

func (e *ExecutionPayloadAndBlobsBundle) unpack(data *executionPayloadAndBlobsBundleJSON) error {
	if data.ExecutionPayload == nil {
		return errors.New("execution payload missing")
	}
	e.ExecutionPayload = data.ExecutionPayload

	if data.BlobsBundle == nil {
		return errors.New("blobs bundle missing")
	}
	e.BlobsBundle = data.BlobsBundle

	return nil
}

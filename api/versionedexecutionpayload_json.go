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

package api

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/pkg/errors"
)

type versionJSON struct {
	Version spec.DataVersion `json:"version"`
}

type bellatrixVersionedExecutionPayloadJSON struct {
	Data *bellatrix.ExecutionPayload `json:"data"`
}
type capellaVersionedExecutionPayloadJSON struct {
	Data *capella.ExecutionPayload `json:"data"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *VersionedExecutionPayload) UnmarshalJSON(input []byte) error {
	var metadata versionJSON
	if err := json.Unmarshal(input, &metadata); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	switch metadata.Version {
	case spec.DataVersionBellatrix:
		var data bellatrixVersionedExecutionPayloadJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Bellatrix = data.Data
	case spec.DataVersionCapella:
		var data capellaVersionedExecutionPayloadJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Capella = data.Data
	default:
		return fmt.Errorf("unsupported data version %v", metadata.Version)
	}

	return nil
}

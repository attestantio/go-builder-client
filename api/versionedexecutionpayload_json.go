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
	"github.com/attestantio/go-eth2-client/spec/deneb"
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

type denebVersionedExecutionPayloadJSON struct {
	Data *deneb.ExecutionPayload `json:"data"`
}

// MarshalJSON implements json.Marshaler.
func (v *VersionedExecutionPayload) MarshalJSON() ([]byte, error) {
	version := &versionJSON{
		Version: v.Version,
	}
	switch v.Version {
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix data")
		}
		data := &bellatrixVersionedExecutionPayloadJSON{
			Data: v.Bellatrix,
		}
		payload := struct {
			*versionJSON
			*bellatrixVersionedExecutionPayloadJSON
		}{version, data}

		return json.Marshal(payload)
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella data")
		}
		data := &capellaVersionedExecutionPayloadJSON{
			Data: v.Capella,
		}
		payload := struct {
			*versionJSON
			*capellaVersionedExecutionPayloadJSON
		}{version, data}

		return json.Marshal(payload)
	case spec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no deneb data")
		}
		data := &denebVersionedExecutionPayloadJSON{
			Data: v.Deneb,
		}
		payload := struct {
			*versionJSON
			*denebVersionedExecutionPayloadJSON
		}{version, data}

		return json.Marshal(payload)
	case spec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no electra data")
		}
		data := &denebVersionedExecutionPayloadJSON{
			Data: v.Electra,
		}
		payload := struct {
			*versionJSON
			*denebVersionedExecutionPayloadJSON
		}{version, data}

		return json.Marshal(payload)
	case spec.DataVersionFulu:
		if v.Fulu == nil {
			return nil, errors.New("no electra data")
		}
		data := &denebVersionedExecutionPayloadJSON{
			Data: v.Fulu,
		}
		payload := struct {
			*versionJSON
			*denebVersionedExecutionPayloadJSON
		}{version, data}

		return json.Marshal(payload)
	default:
		return nil, fmt.Errorf("unsupported data version %v", v.Version)
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *VersionedExecutionPayload) UnmarshalJSON(input []byte) error {
	var metadata versionJSON
	if err := json.Unmarshal(input, &metadata); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	v.Version = metadata.Version
	switch v.Version {
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
	case spec.DataVersionDeneb:
		var data denebVersionedExecutionPayloadJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Deneb = data.Data
	case spec.DataVersionElectra:
		var data denebVersionedExecutionPayloadJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Electra = data.Data
	case spec.DataVersionFulu:
		var data denebVersionedExecutionPayloadJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Fulu = data.Data
	default:
		return fmt.Errorf("unsupported data version %v", metadata.Version)
	}

	return nil
}

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
	"github.com/attestantio/go-builder-client/api/electra"

	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

type denebVersionedExecutionPayloadAndBlobsBundleJSON struct {
	Data *deneb.ExecutionPayloadAndBlobsBundle `json:"data"`
}

type electraVersionedExecutionPayloadAndBlobsBundleJSON struct {
	Data *electra.ExecutionPayloadAndBlobsBundle `json:"data"`
}

// MarshalJSON implements json.Marshaler.
func (v *VersionedSubmitBlindedBlockResponse) MarshalJSON() ([]byte, error) {
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
		data := &denebVersionedExecutionPayloadAndBlobsBundleJSON{
			Data: v.Deneb,
		}
		payload := struct {
			*versionJSON
			*denebVersionedExecutionPayloadAndBlobsBundleJSON
		}{version, data}

		return json.Marshal(payload)
	case spec.DataVersionElectra:
		if v.Electra == nil {
			return nil, errors.New("no electra data")
		}
		data := &electraVersionedExecutionPayloadAndBlobsBundleJSON{
			Data: v.Electra,
		}
		payload := struct {
			*versionJSON
			*electraVersionedExecutionPayloadAndBlobsBundleJSON
		}{version, data}
		return json.Marshal(payload)
	default:
		return nil, fmt.Errorf("unsupported data version %v", v.Version)
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *VersionedSubmitBlindedBlockResponse) UnmarshalJSON(input []byte) error {
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
		var data denebVersionedExecutionPayloadAndBlobsBundleJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Deneb = data.Data
	case spec.DataVersionElectra:
		var data electraVersionedExecutionPayloadAndBlobsBundleJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Electra = data.Data
	default:
		return fmt.Errorf("unsupported data version %v", metadata.Version)
	}

	return nil
}

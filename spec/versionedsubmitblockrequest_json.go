// Copyright © 2023 Attestant Limited.
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

package spec

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

type bellatrixVersionedSubmitBlockRequestJSON struct {
	Data *bellatrix.SubmitBlockRequest `json:"data"`
}
type capellaVersionedSubmitBlockRequestJSON struct {
	Data *capella.SubmitBlockRequest `json:"data"`
}

type denebVersionedSubmitBlockRequestJSON struct {
	Data *deneb.SubmitBlockRequest `json:"data"`
}

// MarshalJSON implements json.Marshaler.
func (v *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	version := &versionJSON{
		Version: v.Version,
	}

	switch v.Version {
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix data")
		}
		data := &bellatrixVersionedSubmitBlockRequestJSON{
			Data: v.Bellatrix,
		}
		payload := struct {
			*versionJSON
			*bellatrixVersionedSubmitBlockRequestJSON
		}{version, data}
		return json.Marshal(payload)
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella data")
		}
		data := &capellaVersionedSubmitBlockRequestJSON{
			Data: v.Capella,
		}
		payload := struct {
			*versionJSON
			*capellaVersionedSubmitBlockRequestJSON
		}{version, data}
		return json.Marshal(payload)
	case spec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no deneb data")
		}
		data := &denebVersionedSubmitBlockRequestJSON{
			Data: v.Deneb,
		}
		payload := struct {
			*versionJSON
			*denebVersionedSubmitBlockRequestJSON
		}{version, data}
		return json.Marshal(payload)
	default:
		return nil, fmt.Errorf("unsupported data version %v", v.Version)
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var metadata versionJSON
	if err := json.Unmarshal(input, &metadata); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	v.Version = metadata.Version
	switch metadata.Version {
	case spec.DataVersionBellatrix:
		var data bellatrixVersionedSubmitBlockRequestJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Bellatrix = data.Data
	case spec.DataVersionCapella:
		var data capellaVersionedSubmitBlockRequestJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Capella = data.Data
	case spec.DataVersionDeneb:
		var data denebVersionedSubmitBlockRequestJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Deneb = data.Data
	default:
		return fmt.Errorf("unsupported data version %v", metadata.Version)
	}

	return nil
}

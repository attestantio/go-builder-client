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

package spec

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

type versionJSON struct {
	Version spec.DataVersion `json:"version"`
}

type bellatrixVersionedSignedBuilderBidJSON struct {
	Data *bellatrix.SignedBuilderBid `json:"data"`
}
type capellaVersionedSignedBuilderBidJSON struct {
	Data *capella.SignedBuilderBid `json:"data"`
}

// MarshalJSON implements json.Marshaler.
func (v *VersionedSignedBuilderBid) MarshalJSON() ([]byte, error) {
	builder := strings.Builder{}
	builder.WriteString(`{"version":"`)
	builder.WriteString(v.Version.String())
	builder.WriteString(`"`)

	var data []byte
	var err error
	switch v.Version {
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			err = fmt.Errorf("no bellatrix data")
			break
		}
		data, err = json.Marshal(v.Bellatrix)
	case spec.DataVersionCapella:
		if v.Capella == nil {
			err = fmt.Errorf("no capella data")
			break
		}
		data, err = json.Marshal(v.Capella)
	default:
		err = fmt.Errorf("unsupported version %v", v.Version)
	}
	if err != nil {
		return nil, err
	}
	if data != nil {
		builder.WriteString(`,"data":`)
		builder.WriteString(string(data))
	}
	builder.WriteString(`}`)
	return []byte(builder.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *VersionedSignedBuilderBid) UnmarshalJSON(input []byte) error {
	var metadata versionJSON
	if err := json.Unmarshal(input, &metadata); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	v.Version = metadata.Version
	switch metadata.Version {
	case spec.DataVersionBellatrix:
		var data bellatrixVersionedSignedBuilderBidJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Bellatrix = data.Data
	case spec.DataVersionCapella:
		var data capellaVersionedSignedBuilderBidJSON
		if err := json.Unmarshal(input, &data); err != nil {
			return errors.Wrap(err, "invalid JSON")
		}
		v.Capella = data.Data
	default:
		return fmt.Errorf("unsupported data version %v", metadata.Version)
	}

	return nil
}

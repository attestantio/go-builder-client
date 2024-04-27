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
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
)

// VersionedExecutionPayloadHeader contains a versioned ExecutionPayloadHeaderV1.
type VersionedExecutionPayloadHeader struct {
	Version   consensusspec.DataVersion         `json:"version"`
	Bellatrix *bellatrix.ExecutionPayloadHeader `json:"bellatrix,omitempty"`
	Capella   *capella.ExecutionPayloadHeader   `json:"capella,omitempty"`
	Deneb     *deneb.ExecutionPayloadHeader     `json:"deneb,omitempty"`
	Electra   *electra.ExecutionPayloadHeader   `json:"electra,omitempty"`
}

// IsEmpty returns true if there is no payload.
func (v *VersionedExecutionPayloadHeader) IsEmpty() bool {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		return v.Bellatrix == nil
	case consensusspec.DataVersionCapella:
		return v.Capella == nil
	case consensusspec.DataVersionDeneb:
		return v.Deneb == nil
	case consensusspec.DataVersionElectra:
		return v.Electra == nil
	default:
		return true
	}
}

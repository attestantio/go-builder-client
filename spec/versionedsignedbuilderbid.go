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
	"errors"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionedSignedBuilderBid contains a versioned signed builder bid.
type VersionedSignedBuilderBid struct {
	Version consensusspec.DataVersion
	Data    *bellatrix.SignedBuilderBid
	Capella *capella.SignedBuilderBid
}

// IsEmpty returns true if there is no bid.
func (v *VersionedSignedBuilderBid) IsEmpty() bool {
	return v.Data == nil && v.Capella == nil
}

// TransactionsRoot returns the transactions root of the bid.
func (v *VersionedSignedBuilderBid) TransactionsRoot() (phase0.Root, error) {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Data == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Data.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Data.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return v.Data.Message.Header.TransactionsRoot, nil
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if v.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if v.Capella.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return v.Capella.Message.Header.TransactionsRoot, nil
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

// String returns a string version of the structure.
func (v *VersionedSignedBuilderBid) String() string {
	switch v.Version {
	case consensusspec.DataVersionBellatrix:
		if v.Data == nil {
			return ""
		}
		return v.Data.String()
	case consensusspec.DataVersionCapella:
		if v.Capella == nil {
			return ""
		}
		return v.Capella.String()
	default:
		return "unknown version"
	}
}

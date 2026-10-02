// Copyright © 2026 Attestant Limited.
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

package gloas

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// builderRequestAuthJSON is the spec representation of the struct.
type builderRequestAuthJSON struct {
	Data string `json:"data"`
	Slot string `json:"slot"`
}

// MarshalJSON implements json.Marshaler.
func (b *BuilderRequestAuth) MarshalJSON() ([]byte, error) {
	return json.Marshal(&builderRequestAuthJSON{
		Data: fmt.Sprintf("%#x", b.Data),
		Slot: strconv.FormatUint(uint64(b.Slot), 10),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BuilderRequestAuth) UnmarshalJSON(input []byte) error {
	var data builderRequestAuthJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return b.unpack(&data)
}

func (b *BuilderRequestAuth) unpack(data *builderRequestAuthJSON) error {
	if data.Data == "" {
		return errors.New("data missing")
	}

	authData, err := hex.DecodeString(strings.TrimPrefix(data.Data, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for data")
	}

	if len(authData) == 0 {
		return errors.New("data missing")
	}

	if len(authData) > MaxBuilderAuthDataSize {
		return errors.New("data too long")
	}

	b.Data = authData

	if data.Slot == "" {
		return errors.New("slot missing")
	}

	slot, err := strconv.ParseUint(data.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}

	b.Slot = phase0.Slot(slot)

	return nil
}

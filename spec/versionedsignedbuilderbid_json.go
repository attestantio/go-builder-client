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
)

// MarshalJSON implements json.Marshaler.
func (v *VersionedSignedBuilderBid) MarshalJSON() ([]byte, error) {
	builder := strings.Builder{}
	builder.WriteString(`{"version":"`)
	builder.WriteString(v.Version.String())
	builder.WriteString(`","data":`)
	var data []byte
	var err error
	switch {
	case v.Data != nil:
		data, err = json.Marshal(v.Data)
	case v.Capella != nil:
		data, err = json.Marshal(v.Capella)
	default:
		err = fmt.Errorf("unsupported version %v", v.Version)
	}
	if err != nil {
		return nil, err
	}
	builder.WriteString(string(data))
	builder.WriteString(`}`)
	return []byte(builder.String()), nil
}

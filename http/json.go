// Copyright © 2024 Attestant Limited.
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

package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/huandu/go-clone"
)

func decodeJSONResponse[T any](body io.Reader, res T) (T, map[string]any, error) {
	if body == nil {
		return res, nil, errors.New("no body to read")
	}

	decoded := make(map[string]json.RawMessage)

	if err := json.NewDecoder(body).Decode(&decoded); err != nil {
		return res, nil, errors.Join(errors.New("failed to parse JSON"), err)
	}

	//nolint:forcetypeassert
	data := clone.Clone(res).(T)
	metadata := make(map[string]any)
	for k, v := range decoded {
		switch k {
		case "data":
			err := json.Unmarshal(v, &data)
			if err != nil {
				return res, nil, errors.Join(errors.New("failed to unmarshal data"), err)
			}
		default:
			var val any
			err := json.Unmarshal(v, &val)
			if err != nil {
				return res, nil, errors.Join(fmt.Errorf("failed to unmarshal metadata %s", k), err)
			}
			metadata[k] = val
		}
	}

	return data, metadata, nil
}

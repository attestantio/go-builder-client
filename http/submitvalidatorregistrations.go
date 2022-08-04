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

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/pkg/errors"
)

var submitValidatorRegistrationsChunkSize = 1000

// SubmitValidatorRegistrations submits a validator registration.
func (s *Service) SubmitValidatorRegistrations(ctx context.Context,
	registrations []*api.VersionedSignedValidatorRegistration,
) error {
	started := time.Now()

	if len(registrations) == 0 {
		return errors.New("no registrations supplied")
	}

	if len(registrations) > submitValidatorRegistrationsChunkSize {
		return s.chunkedSubmitValidatorRegistrations(ctx, registrations)
	}

	// Unwrap versioned registrations.
	var version *spec.BuilderVersion
	var unversionedRegistrations []interface{}

	for _, registration := range registrations {
		if registration == nil {
			monitorOperation(s.Address(), "submitvalidatorregistrations", false, time.Since(started))
			return errors.New("nil registration supplied")
		}

		// Ensure consistent versioning.
		if version == nil {
			version = &registration.Version
		} else if *version != registration.Version {
			monitorOperation(s.Address(), "submitvalidatorregistrations", false, time.Since(started))
			return errors.New("registrations must all be of the same version")
		}

		// Append to unversionedRegistrations.
		switch registration.Version {
		case spec.BuilderVersionV1:
			unversionedRegistrations = append(unversionedRegistrations, registration.V1)
		default:
			monitorOperation(s.Address(), "submitvalidatorregistrations", false, time.Since(started))
			return errors.New("unknown validator registration version")
		}
	}

	specJSON, err := json.Marshal(unversionedRegistrations)
	if err != nil {
		monitorOperation(s.Address(), "submitvalidatorregistrations", false, time.Since(started))
		return errors.Wrap(err, "failed to marshal JSON")
	}
	_, _, err = s.post(ctx, "/eth/v1/builder/validators", ContentTypeJSON, bytes.NewBuffer(specJSON))
	if err != nil {
		monitorOperation(s.Address(), "submitvalidatorregistrations", false, time.Since(started))
		return errors.Wrap(err, "failed to submit validator registration")
	}

	monitorOperation(s.Address(), "submitvalidatorregistrations", true, time.Since(started))
	return nil
}

// chunkedSubmitValidatorRegistrations submits validator registrations in chunks.
func (s *Service) chunkedSubmitValidatorRegistrations(ctx context.Context,
	registrations []*api.VersionedSignedValidatorRegistration,
) error {
	chunkSize := submitValidatorRegistrationsChunkSize
	for i := 0; i < len(registrations); i += chunkSize {
		chunkStart := i
		chunkEnd := i + chunkSize
		if len(registrations) < chunkEnd {
			chunkEnd = len(registrations)
		}
		chunk := registrations[chunkStart:chunkEnd]
		err := s.SubmitValidatorRegistrations(ctx, chunk)
		if err != nil {
			return errors.Wrap(err, "failed to submit chunk")
		}
	}
	return nil
}

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
	"errors"

	client "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var submitValidatorRegistrationsChunkSize = 500

// SubmitValidatorRegistrations submits a validator registration.
func (s *Service) SubmitValidatorRegistrations(ctx context.Context,
	opts *api.SubmitValidatorRegistrationsOpts,
) error {
	if opts == nil {
		return client.ErrNoOptions
	}

	if len(opts.Registrations) == 0 {
		return errors.Join(errors.New("no validator registrations specified"), client.ErrInvalidOptions)
	}

	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "SubmitValidatorRegistrations", trace.WithAttributes(
		attribute.Int("validators", len(opts.Registrations)),
	))
	defer span.End()

	var err error
	if len(opts.Registrations) <= submitValidatorRegistrationsChunkSize {
		err = s.submitValidatorRegistrations(ctx, opts)
	} else {
		err = s.submitChunkedValidatorRegistrations(ctx, opts)
	}

	if err != nil {
		return errors.Join(errors.New("failed to submit validator registrations"), err)
	}

	return nil
}

//nolint:revive
func (s *Service) submitValidatorRegistrations(ctx context.Context,
	opts *api.SubmitValidatorRegistrationsOpts,
) error {
	// Unwrap versioned registrations.
	var (
		version                  *spec.BuilderVersion
		unversionedRegistrations []any
	)

	for _, registration := range opts.Registrations {
		if registration == nil {
			return errors.New("nil registration supplied")
		}

		// Ensure consistent versioning.
		if version == nil {
			version = &registration.Version
		} else if *version != registration.Version {
			return errors.New("registrations must all be of the same version")
		}

		// Append to unversionedRegistrations.
		switch registration.Version {
		case spec.BuilderVersionV1:
			unversionedRegistrations = append(unversionedRegistrations, registration.V1)
		default:
			return errors.New("unknown validator registration version")
		}
	}

	specJSON, err := json.Marshal(unversionedRegistrations)
	if err != nil {
		return errors.Join(errors.New("failed to marshal JSON"), err)
	}

	_, err = s.post(ctx,
		"/eth/v1/builder/validators",
		"",
		&opts.Common,
		bytes.NewBuffer(specJSON),
		ContentTypeJSON,
		map[string]string{},
		false,
	)
	if err != nil {
		return errors.Join(errors.New("failed to submit validator registration"), err)
	}

	return nil
}

// submitChunkedValidatorRegistrations submits validator registrations in chunks.
func (s *Service) submitChunkedValidatorRegistrations(ctx context.Context,
	opts *api.SubmitValidatorRegistrationsOpts,
) error {
	chunkSize := submitValidatorRegistrationsChunkSize
	for i := 0; i < len(opts.Registrations); i += chunkSize {
		chunkStart := i

		chunkEnd := i + chunkSize
		if len(opts.Registrations) < chunkEnd {
			chunkEnd = len(opts.Registrations)
		}

		err := s.submitValidatorRegistrations(ctx, &api.SubmitValidatorRegistrationsOpts{
			Common:        opts.Common,
			Registrations: opts.Registrations[chunkStart:chunkEnd],
		})
		if err != nil {
			return errors.Join(errors.New("failed to submit chunk"), err)
		}
	}

	return nil
}

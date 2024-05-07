// Copyright © 2022, 2024 Attestant Limited.
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
	"fmt"
	"time"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BuilderBid obtains a builder bid.
func (s *Service) BuilderBid(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubKey phase0.BLSPubKey,
) (
	*spec.VersionedSignedBuilderBid,
	error,
) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "BuilderBid", trace.WithAttributes(
		attribute.String("relay", s.Address()),
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()
	started := time.Now()

	endpoint := fmt.Sprintf("/eth/v1/builder/header/%d/%#x/%#x", slot, parentHash[:], pubKey[:])
	httpResponse, err := s.get(ctx, endpoint, "")
	if err != nil {
		log.Trace().Str("endpoint", endpoint).Err(err).Msg("Request failed")
		monitorOperation(s.Address(), "builder bid", "failed", time.Since(started))

		return nil, errors.Wrap(err, "failed to request execution payload header")
	}

	if len(httpResponse.body) == 0 {
		monitorOperation(s.Address(), "builder bid", "no response", time.Since(started))

		//nolint:nilnil
		return nil, nil
	}

	res := &spec.VersionedSignedBuilderBid{
		Version: httpResponse.consensusVersion,
	}

	switch httpResponse.contentType {
	case ContentTypeJSON:
		switch httpResponse.consensusVersion {
		case consensusspec.DataVersionBellatrix:
			res.Bellatrix, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), &bellatrix.SignedBuilderBid{})
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse bellatrix builder bid")
			}
			if !bytes.Equal(res.Bellatrix.Message.Header.ParentHash[:], parentHash[:]) {
				return nil, errors.New("parent hash mismatch")
			}
		case consensusspec.DataVersionCapella:
			res.Capella, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), &capella.SignedBuilderBid{})
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse capella builder bid")
			}
			if !bytes.Equal(res.Capella.Message.Header.ParentHash[:], parentHash[:]) {
				return nil, errors.New("parent hash mismatch")
			}
		case consensusspec.DataVersionDeneb:
			res.Deneb, _, err = decodeJSONResponse(bytes.NewReader(httpResponse.body), &deneb.SignedBuilderBid{})
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse deneb builder bid")
			}
			if !bytes.Equal(res.Deneb.Message.Header.ParentHash[:], parentHash[:]) {
				return nil, errors.New("parent hash mismatch")
			}
		default:
			return nil, fmt.Errorf("unsupported block version %s", httpResponse.consensusVersion)
		}
	default:
		return nil, fmt.Errorf("unsupported content type %v", httpResponse.contentType)
	}

	monitorOperation(s.Address(), "builder bid", "succeeded", time.Since(started))

	value, err := res.Value()
	if err == nil {
		span.SetAttributes(
			// Has to be a string due to the potential size being >maxint64.
			attribute.String("value", value.ToBig().String()),
		)
	}

	return res, nil
}

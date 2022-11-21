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
	"fmt"
	"io"
	"time"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type bellatrixBuilderBidJSON struct {
	Data *bellatrix.SignedBuilderBid `json:"data"`
}

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
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()
	started := time.Now()

	url := fmt.Sprintf("/eth/v1/builder/header/%d/%#x/%#x", slot, parentHash[:], pubKey[:])
	contentType, respBodyReader, err := s.get(ctx, url)
	if err != nil {
		log.Trace().Str("url", url).Err(err).Msg("Request failed")
		monitorOperation(s.Address(), "builder bid", "failed", time.Since(started))
		return nil, errors.Wrap(err, "failed to request execution payload header")
	}
	if respBodyReader == nil {
		monitorOperation(s.Address(), "builder bid", "no response", time.Since(started))
		return nil, nil
	}

	var dataBodyReader bytes.Buffer
	metadataReader := io.TeeReader(respBodyReader, &dataBodyReader)
	var metadata responseMetadata
	if err := json.NewDecoder(metadataReader).Decode(&metadata); err != nil {
		monitorOperation(s.Address(), "builder bid", "failed", time.Since(started))
		return nil, errors.Wrap(err, "failed to parse response")
	}
	res := &spec.VersionedSignedBuilderBid{
		Version: metadata.Version,
	}

	switch contentType {
	case ContentTypeJSON:
		switch metadata.Version {
		case consensusspec.DataVersionBellatrix:
			var resp bellatrixBuilderBidJSON
			if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
				return nil, errors.Wrap(err, "failed to parse bellatrix builder bid")
			}
			if !bytes.Equal(resp.Data.Message.Header.ParentHash[:], parentHash[:]) {
				return nil, errors.New("parent hash mismatch")
			}
			res.Data = resp.Data
		default:
			return nil, fmt.Errorf("unsupported block version %s", metadata.Version)
		}
	default:
		return nil, fmt.Errorf("unsupported content type %v", contentType)
	}

	monitorOperation(s.Address(), "builder bid", "succeeded", time.Since(started))
	return res, nil
}

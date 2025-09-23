// Copyright © 2022 - 2025 Attestant Limited.
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
	"errors"
	"fmt"
	"net/http"
	"time"

	client "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BuilderBid obtains a builder bid.
func (s *Service) BuilderBid(ctx context.Context,
	opts *api.BuilderBidOpts,
) (
	*api.Response[*spec.VersionedSignedBuilderBid],
	error,
) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "BuilderBid", trace.WithAttributes(
		attribute.String("relay", s.Address()),
	))
	defer span.End()

	if opts == nil {
		return nil, client.ErrNoOptions
	}

	span.SetAttributes(attribute.Int64("slot", int64(opts.Slot)))

	var emptyHash phase0.Hash32
	if bytes.Equal(opts.ParentHash[:], emptyHash[:]) {
		return nil, errors.Join(errors.New("no parent hash specified"), client.ErrInvalidOptions)
	}
	var emptyPubKey phase0.BLSPubKey
	if bytes.Equal(opts.PubKey[:], emptyPubKey[:]) {
		return nil, errors.Join(errors.New("no public key specified"), client.ErrInvalidOptions)
	}

	headers := make(map[string]string)
	headers["Date-Milliseconds"] = fmt.Sprintf("%d", time.Now().UnixMilli())

	endpoint := fmt.Sprintf("/eth/v1/builder/header/%d/%#x/%#x", opts.Slot, opts.ParentHash[:], opts.PubKey[:])
	httpResponse, err := s.get(ctx,
		endpoint,
		"",
		&opts.Common,
		headers,
		true,
	)
	if err != nil {
		return nil, errors.Join(errors.New("failed to request execution payload header"), err)
	}

	if httpResponse.statusCode == http.StatusNoContent {
		// This is a valid response when the relay has no suitable bid.
		return &api.Response[*spec.VersionedSignedBuilderBid]{
			Data:     nil,
			Metadata: metadataFromHeaders(httpResponse.headers),
		}, nil
	}

	var response *api.Response[*spec.VersionedSignedBuilderBid]

	switch httpResponse.contentType {
	case ContentTypeSSZ:
		response, err = s.signedBuilderBidFromSSZ(ctx, httpResponse)
	case ContentTypeJSON:
		response, err = s.signedBuilderBidFromJSON(httpResponse)
	default:
		return nil, fmt.Errorf("unhandled content type %v", httpResponse.contentType)
	}
	if err != nil {
		return nil, err
	}

	parentHash, err := response.Data.ParentHash()
	if err != nil {
		return nil, errors.Join(errors.New("could not obtain parent hash of bid"), err)
	}
	if !bytes.Equal(parentHash[:], opts.ParentHash[:]) {
		return nil, errors.New("parent hash mismatch")
	}

	value, err := response.Data.Value()
	if err == nil {
		span.SetAttributes(
			// Has to be a string due to the potential size being >maxint64.
			attribute.String("value", value.ToBig().String()),
		)
	}

	return response, nil
}

func (*Service) signedBuilderBidFromJSON(res *httpResponse) (
	*api.Response[*spec.VersionedSignedBuilderBid],
	error,
) {
	response := &api.Response[*spec.VersionedSignedBuilderBid]{
		Data: &spec.VersionedSignedBuilderBid{
			Version: res.consensusVersion,
		},
		Metadata: metadataFromHeaders(res.headers),
	}

	var err error
	switch res.consensusVersion {
	case consensusspec.DataVersionBellatrix:
		response.Data.Bellatrix, _, err = decodeJSONResponse(bytes.NewReader(res.body),
			&bellatrix.SignedBuilderBid{},
		)
	case consensusspec.DataVersionCapella:
		response.Data.Capella, _, err = decodeJSONResponse(bytes.NewReader(res.body),
			&capella.SignedBuilderBid{},
		)
	case consensusspec.DataVersionDeneb:
		response.Data.Deneb, _, err = decodeJSONResponse(bytes.NewReader(res.body),
			&deneb.SignedBuilderBid{},
		)
	case consensusspec.DataVersionElectra:
		response.Data.Electra, _, err = decodeJSONResponse(bytes.NewReader(res.body),
			&electra.SignedBuilderBid{},
		)
	case consensusspec.DataVersionFulu:
		response.Data.Fulu, _, err = decodeJSONResponse(bytes.NewReader(res.body),
			&electra.SignedBuilderBid{},
		)
	default:
		return nil, fmt.Errorf("unsupported block version %s", res.consensusVersion)
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (*Service) signedBuilderBidFromSSZ(_ context.Context,
	res *httpResponse,
) (
	*api.Response[*spec.VersionedSignedBuilderBid],
	error,
) {
	response := &api.Response[*spec.VersionedSignedBuilderBid]{
		Data: &spec.VersionedSignedBuilderBid{
			Version: res.consensusVersion,
		},
		Metadata: metadataFromHeaders(res.headers),
	}

	var err error
	switch res.consensusVersion {
	case consensusspec.DataVersionBellatrix:
		response.Data.Bellatrix = &bellatrix.SignedBuilderBid{}
		err = response.Data.Bellatrix.UnmarshalSSZ(res.body)
	case consensusspec.DataVersionCapella:
		response.Data.Capella = &capella.SignedBuilderBid{}
		err = response.Data.Capella.UnmarshalSSZ(res.body)
	case consensusspec.DataVersionDeneb:
		response.Data.Deneb = &deneb.SignedBuilderBid{}
		err = response.Data.Deneb.UnmarshalSSZ(res.body)
	case consensusspec.DataVersionElectra:
		response.Data.Electra = &electra.SignedBuilderBid{}
		err = response.Data.Electra.UnmarshalSSZ(res.body)
	case consensusspec.DataVersionFulu:
		response.Data.Fulu = &electra.SignedBuilderBid{}
		err = response.Data.Fulu.UnmarshalSSZ(res.body)
	default:
		return nil, fmt.Errorf("unsupported block version %s", res.consensusVersion)
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

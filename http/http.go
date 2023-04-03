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
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// get sends an HTTP get request and returns the body.
// If the response from the server is a 404 this will return nil for both the reader and the error.
func (s *Service) get(ctx context.Context, endpoint string) (ContentType, io.Reader, error) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "get")
	defer span.End()

	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("endpoint", endpoint).Str("address", s.address).Logger()
	log.Trace().Msg("GET request")

	url, err := url.Parse(fmt.Sprintf("%s%s", strings.TrimSuffix(s.base.String(), "/"), endpoint))
	if err != nil {
		return ContentTypeUnknown, nil, errors.Wrap(err, "invalid endpoint")
	}
	span.SetAttributes(attribute.String("url", url.String()))

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	req, err := http.NewRequestWithContext(opCtx, http.MethodGet, url.String(), nil)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Failed to create request")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to create GET request")
	}

	// Prefer SSZ if available (enable when we support SSZ) .
	// req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	req.Header.Set("Accept", "application/json")
	span.AddEvent("Sending request")
	resp, err := s.client.Do(req)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Request failed")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to call GET endpoint")
	}
	defer resp.Body.Close()
	log = log.With().Int("status_code", resp.StatusCode).Logger()

	if resp.StatusCode == http.StatusNotFound {
		// Nothing found.  This is not an error, so we return nil on both counts.
		cancel()
		span.RecordError(errors.New("endpoint not found"))
		log.Debug().Msg("Endpoint not found")
		return ContentTypeUnknown, nil, nil
	}

	if resp.StatusCode == http.StatusNoContent {
		// Nothing returned.  This is not an error, so we return nil on both counts.
		cancel()
		span.AddEvent("Received empty response")
		log.Trace().Msg("Endpoint returned no content")
		return ContentTypeUnknown, nil, nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Failed to read response")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to read GET response")
	}
	span.AddEvent("Received response", trace.WithAttributes(attribute.Int("size", len(data))))

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		cancel()
		trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(data, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
		log.Debug().Int("status_code", resp.StatusCode).RawJSON("response", trimmedResponse).Msg("GET failed")
		span.SetStatus(codes.Error, fmt.Sprintf("Status code %d", resp.StatusCode))
		return ContentTypeUnknown, nil, fmt.Errorf("GET failed with status %d: %s", resp.StatusCode, string(data))
	}
	cancel()

	contentType, err := contentTypeFromResp(resp)
	if err != nil {
		// For now, assume that unknown type is JSON.
		log.Debug().Err(err).Msg("Failed to obtain content type; assuming JSON")
		contentType = ContentTypeJSON
	}

	return contentType, bytes.NewReader(data), nil
}

// post sends an HTTP post request and returns the body.
func (s *Service) post(ctx context.Context, endpoint string, contentType ContentType, body io.Reader) (ContentType, io.Reader, error) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "post")
	defer span.End()

	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("endpoint", endpoint).Str("address", s.address).Logger()
	if e := log.Trace(); e.Enabled() {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			return ContentTypeUnknown, nil, errors.New("failed to read request body")
		}
		body = bytes.NewReader(bodyBytes)

		e.RawJSON("body", bodyBytes).Msg("POST request")
	}

	url, err := url.Parse(fmt.Sprintf("%s%s", strings.TrimSuffix(s.base.String(), "/"), endpoint))
	if err != nil {
		return ContentTypeUnknown, nil, errors.Wrap(err, "invalid endpoint")
	}
	span.SetAttributes(attribute.String("url", url.String()))

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	req, err := http.NewRequestWithContext(opCtx, http.MethodPost, url.String(), body)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Failed to create request")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to create POST request")
	}

	req.Header.Set("Content-type", contentType.MediaType())
	// Prefer SSZ if available (enable when we support SSZ) .
	// req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	req.Header.Set("Accept", "application/json")
	span.AddEvent("Sending request")
	resp, err := s.client.Do(req)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Request failed")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to call POST endpoint")
	}
	defer resp.Body.Close()
	log = log.With().Int("status_code", resp.StatusCode).Logger()

	if resp.StatusCode == http.StatusNoContent {
		// Nothing returned.  This is not an error, so we return nil on both counts.
		cancel()
		span.AddEvent("Received empty response")
		log.Trace().Msg("Endpoint returned no content")
		return ContentTypeUnknown, nil, nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		cancel()
		span.SetStatus(codes.Error, "Failed to read response")
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to read POST response")
	}
	span.AddEvent("Received response", trace.WithAttributes(attribute.Int("size", len(data))))

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(data, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
		log.Debug().Int("status_code", resp.StatusCode).RawJSON("response", trimmedResponse).Msg("POST failed")
		cancel()
		span.SetStatus(codes.Error, fmt.Sprintf("Status code %d", resp.StatusCode))
		return ContentTypeUnknown, nil, fmt.Errorf("POST failed with status %d: %s", resp.StatusCode, string(data))
	}
	cancel()

	log.Trace().RawJSON("response", bytes.TrimSuffix(data, []byte{0x0a})).Msg("POST response")

	return contentType, bytes.NewReader(data), nil
}

// responseMetadata returns metadata related to responses.
type responseMetadata struct {
	Version consensusspec.DataVersion `json:"version"`
}

func contentTypeFromResp(resp *http.Response) (ContentType, error) {
	respContentType, exists := resp.Header["Content-Type"]
	if !exists {
		return ContentTypeUnknown, errors.New("no content type supplied in response")
	}
	if len(respContentType) != 1 {
		return ContentTypeUnknown, fmt.Errorf("malformed content type (%d entries)", len(respContentType))
	}
	return ParseFromMediaType(respContentType[0])
}

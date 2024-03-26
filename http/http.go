// Copyright © 2022 - 2024 Attestant Limited.
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
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/attestantio/go-eth2-client/spec"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type httpResponse struct {
	statusCode       int
	contentType      ContentType
	headers          map[string]string
	consensusVersion spec.DataVersion
	body             []byte
}

// responseMetadata returns metadata related to responses.
type responseMetadata struct {
	Version spec.DataVersion `json:"version"`
}

// get sends an HTTP get request and returns the response.
func (s *Service) get(ctx context.Context,
	endpoint string,
	query string,
) (
	*httpResponse,
	error,
) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "get")
	defer span.End()

	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("address", s.address).Str("endpoint", endpoint).Logger()
	log.Trace().Msg("GET request")

	url := urlForCall(s.base, endpoint, query)
	log.Trace().Str("url", url.String()).Msg("URL to GET")
	span.SetAttributes(attribute.String("url", url.String()))

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(opCtx, http.MethodGet, url.String(), nil)
	if err != nil {
		span.SetStatus(codes.Error, "Failed to create request")
		return nil, errors.Join(errors.New("failed to create GET request"), err)
	}

	s.addExtraHeaders(req)
	// Prefer SSZ if available (enable when we support SSZ) .
	// req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	req.Header.Set("Accept", "application/json")
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "go-builder-client/0.4.5")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return nil, errors.Join(errors.New("failed to call GET endpoint"), err)
	}
	defer resp.Body.Close()
	log = log.With().Int("status_code", resp.StatusCode).Logger()

	res := &httpResponse{
		statusCode: resp.StatusCode,
	}
	populateHeaders(res, resp)

	// Although it would be more efficient to keep the body as a Reader, that would
	// require the calling function to be aware that it needs to close the body
	// once it is done with it.  To avoid that complexity, we read here and store the
	// body as a byte array.
	res.body, err = io.ReadAll(resp.Body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return nil, errors.Join(errors.New("failed to read GET response"), err)
	}

	if resp.StatusCode == http.StatusNoContent || len(res.body) == 0 {
		// Nothing returned.  This is not considered an error.
		span.AddEvent("Received empty response")
		log.Trace().Msg("Endpoint returned no content")

		return res, nil
	}

	if err := populateContentType(res, resp); err != nil {
		// For now, assume that unknown type is JSON.
		log.Debug().Err(err).Msg("Failed to obtain content type; assuming JSON")
		res.contentType = ContentTypeJSON
	}
	span.AddEvent("Received response", trace.WithAttributes(
		attribute.Int("size", len(res.body)),
		attribute.String("content-type", res.contentType.String()),
	))

	if res.contentType == ContentTypeJSON {
		if e := log.Trace(); e.Enabled() {
			trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(res.body, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
			e.RawJSON("body", trimmedResponse).Msg("GET response")
		}
	}

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(res.body, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
		log.Debug().Int("status_code", resp.StatusCode).RawJSON("response", trimmedResponse).Msg("GET failed")

		span.SetStatus(codes.Error, fmt.Sprintf("Status code %d", resp.StatusCode))

		return nil, fmt.Errorf("GET failed with status %d: %s", resp.StatusCode, string(res.body))
	}

	if err := populateConsensusVersion(res, resp); err != nil {
		return nil, errors.Join(errors.New("failed to parse consensus version"), err)
	}

	return res, nil
}

// post sends an HTTP post request and returns the body.
//
//nolint:unparam
func (s *Service) post(ctx context.Context,
	endpoint string,
	query string,
	body io.Reader,
	contentType ContentType,
	headers map[string]string,
) (
	*httpResponse,
	error,
) {
	ctx, span := otel.Tracer("attestantio.go-builder-client.http").Start(ctx, "post")
	defer span.End()

	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("endpoint", endpoint).Str("address", s.address).Logger()
	if e := log.Trace(); e.Enabled() {
		switch contentType {
		case ContentTypeJSON:
			bodyBytes, err := io.ReadAll(body)
			if err != nil {
				return nil, errors.New("failed to read request body")
			}
			body = bytes.NewReader(bodyBytes)

			e.Str("body", string(bodyBytes)).Msg("POST request")
		default:
			e.Str("content_type", contentType.String()).Msg("POST request")
		}
	}

	url := urlForCall(s.base, endpoint, query)
	log.Trace().Str("url", url.String()).Msg("URL to POST")
	span.SetAttributes(attribute.String("url", url.String()))

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(opCtx, http.MethodPost, url.String(), body)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create POST request"), err)
	}

	s.addExtraHeaders(req)
	req.Header.Set("Content-Type", contentType.MediaType())
	// Prefer SSZ if available (enable when we support SSZ) .
	// req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "go-builder-client/0.4.5")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "Request failed")

		return nil, errors.Join(errors.New("failed to call POST endpoint"), err)
	}
	defer resp.Body.Close()
	log = log.With().Int("status_code", resp.StatusCode).Logger()

	res := &httpResponse{
		statusCode: resp.StatusCode,
	}
	populateHeaders(res, resp)

	res.body, err = io.ReadAll(resp.Body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return nil, errors.Join(errors.New("failed to read POST response"), err)
	}

	if resp.StatusCode == http.StatusNoContent || len(res.body) == 0 {
		// Nothing returned.  This is not considered an error.
		span.AddEvent("Received empty response")
		log.Trace().Msg("Endpoint returned no content")

		return res, nil
	}

	if err := populateContentType(res, resp); err != nil {
		// For now, assume that unknown type is JSON.
		log.Debug().Err(err).Msg("Failed to obtain content type; assuming JSON")
		res.contentType = ContentTypeJSON
	}
	span.AddEvent("Received response", trace.WithAttributes(
		attribute.Int("size", len(res.body)),
		attribute.String("content-type", res.contentType.String()),
	))

	if res.contentType == ContentTypeJSON {
		if e := log.Trace(); e.Enabled() {
			trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(res.body, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
			e.RawJSON("body", trimmedResponse).Msg("GET response")
		}
	}

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		trimmedResponse := bytes.ReplaceAll(bytes.ReplaceAll(res.body, []byte{0x0a}, []byte{}), []byte{0x0d}, []byte{})
		log.Debug().Int("status_code", resp.StatusCode).RawJSON("response", trimmedResponse).Msg("POST failed")

		span.SetStatus(codes.Error, fmt.Sprintf("Status code %d", resp.StatusCode))

		return nil, fmt.Errorf("POST failed with status %d: %s", resp.StatusCode, string(res.body))
	}

	return res, nil
}

func populateConsensusVersion(res *httpResponse, resp *http.Response) error {
	res.consensusVersion = spec.DataVersionUnknown
	respConsensusVersions, exists := resp.Header["Eth-Consensus-Version"]
	if !exists {
		// No consensus version supplied in response; obtain it from the body if possible.
		if res.contentType != ContentTypeJSON {
			// Not present here either.  Many responses do not provide this information, so assume
			// this is one of them.
			return nil
		}
		var metadata responseMetadata
		if err := json.Unmarshal(res.body, &metadata); err != nil {
			return errors.Join(errors.New("no consensus version header and failed to parse response"), err)
		}
		res.consensusVersion = metadata.Version

		return nil
	}
	if len(respConsensusVersions) != 1 {
		return fmt.Errorf("malformed consensus version (%d entries)", len(respConsensusVersions))
	}
	if err := res.consensusVersion.UnmarshalJSON([]byte(fmt.Sprintf("%q", respConsensusVersions[0]))); err != nil {
		return errors.Join(errors.New("failed to parse consensus version"), err)
	}

	return nil
}

func (s *Service) addExtraHeaders(req *http.Request) {
	for k, v := range s.extraHeaders {
		req.Header.Add(k, v)
	}
}

func populateHeaders(res *httpResponse, resp *http.Response) {
	res.headers = make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		res.headers[k] = strings.Join(v, ";")
	}
}

func populateContentType(res *httpResponse, resp *http.Response) error {
	respContentTypes, exists := resp.Header["Content-Type"]
	if !exists {
		return errors.New("no content type supplied in response")
	}
	if len(respContentTypes) != 1 {
		return fmt.Errorf("malformed content type (%d entries)", len(respContentTypes))
	}

	var err error
	res.contentType, err = ParseFromMediaType(respContentTypes[0])
	if err != nil {
		return err
	}

	return nil
}

// urlForCall patches together a URL for a call.
func urlForCall(base *url.URL, endpoint string, query string) *url.URL {
	callURL := *base
	callURL.Path = endpoint
	if callURL.RawQuery == "" {
		callURL.RawQuery = query
	} else if query != "" {
		callURL.RawQuery = fmt.Sprintf("%s&%s", callURL.RawQuery, query)
	}

	return &callURL
}

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
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

func init() {
	// We seed math.rand here so that we can obtain different IDs for requests.
	// This is purely used as a way to match request and response entries in logs, so there is no
	// requirement for this to cryptographically secure.
	rand.Seed(time.Now().UnixNano())
}

// get sends an HTTP get request and returns the body.
// If the response from the server is a 404 this will return nil for both the reader and the error.
func (s *Service) get(ctx context.Context, endpoint string) (ContentType, io.Reader, error) {
	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("address", s.address).Logger()
	log.Trace().Str("endpoint", endpoint).Msg("GET request")

	url, err := url.Parse(fmt.Sprintf("%s%s", strings.TrimSuffix(s.base.String(), "/"), endpoint))
	if err != nil {
		return ContentTypeUnknown, nil, errors.Wrap(err, "invalid endpoint")
	}

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	req, err := http.NewRequestWithContext(opCtx, http.MethodGet, url.String(), nil)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to create GET request")
	}

	// Prefer SSZ if available.
	req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	resp, err := s.client.Do(req)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to call GET endpoint")
	}

	if resp.StatusCode == 404 {
		// Nothing found.  This is not an error, so we return nil on both counts.
		cancel()
		return ContentTypeUnknown, nil, nil
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to read GET response")
	}

	if e := log.Trace(); e.Enabled() {
		e.Str("endpoint", endpoint).RawJSON("response", data).Msg("GET response")
	}

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		cancel()
		log.Trace().Str("endpoint", endpoint).Int("status_code", resp.StatusCode).Str("data", string(data)).Msg("GET failed")
		return ContentTypeUnknown, nil, fmt.Errorf("GET failed with status %d: %s", resp.StatusCode, string(data))
	}
	cancel()

	contentType, err := contentTypeFromResp(resp)
	if err != nil {
		return ContentTypeUnknown, nil, err
	}

	return contentType, bytes.NewReader(data), nil
}

// post sends an HTTP post request and returns the body.
func (s *Service) post(ctx context.Context, endpoint string, contentType ContentType, body io.Reader) (ContentType, io.Reader, error) {
	// #nosec G404
	log := log.With().Str("id", fmt.Sprintf("%02x", rand.Int31())).Str("address", s.address).Logger()
	if e := log.Trace(); e.Enabled() {
		bodyBytes, err := ioutil.ReadAll(body)
		if err != nil {
			return ContentTypeUnknown, nil, errors.New("failed to read request body")
		}
		body = bytes.NewReader(bodyBytes)

		e.Str("endpoint", endpoint).RawJSON("body", bodyBytes).Msg("POST request")
	}

	url, err := url.Parse(fmt.Sprintf("%s%s", strings.TrimSuffix(s.base.String(), "/"), endpoint))
	if err != nil {
		return ContentTypeUnknown, nil, errors.Wrap(err, "invalid endpoint")
	}

	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	req, err := http.NewRequestWithContext(opCtx, http.MethodPost, url.String(), body)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to create POST request")
	}

	req.Header.Set("Content-type", contentType.MediaType())
	// Prefer SSZ if available.
	req.Header.Set("Accept", "application/octet-stream;q=1,application/json;q=0.9")
	resp, err := s.client.Do(req)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to call POST endpoint")
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		cancel()
		return ContentTypeUnknown, nil, errors.Wrap(err, "failed to read POST response")
	}

	statusFamily := resp.StatusCode / 100
	if statusFamily != 2 {
		log.Trace().Str("endpoint", endpoint).Int("status_code", resp.StatusCode).Str("data", string(data)).Msg("POST failed")
		cancel()
		return ContentTypeUnknown, nil, fmt.Errorf("POST failed with status %d: %s", resp.StatusCode, string(data))
	}
	cancel()

	log.Trace().Str("response", string(data)).Msg("POST response")

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

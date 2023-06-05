// Copyright © 2022, 2023 Attestant Limited.
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
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a builder client service.
type Service struct {
	base         *url.URL
	address      string
	client       *http.Client
	timeout      time.Duration
	pubkey       *phase0.BLSPubKey
	extraHeaders map[string]string
}

// log is a service-wide logger.
var log zerolog.Logger

// New creates a new builder client service, connecting with HTTP.
func New(ctx context.Context, params ...Parameter) (builderclient.Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "client").Str("impl", "http").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if parameters.monitor != nil {
		if err := registerMetrics(ctx, parameters.monitor); err != nil {
			return nil, errors.Wrap(err, "problem registering metrics")
		}
	}

	client := &http.Client{
		Timeout: parameters.timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   parameters.timeout,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:        64,
			MaxConnsPerHost:     64,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     600 * time.Second,
		},
	}

	address := parameters.address
	if !strings.HasPrefix(address, "http") {
		address = fmt.Sprintf("http://%s", address)
	}
	if !strings.HasSuffix(address, "/") {
		address = fmt.Sprintf("%s/", address)
	}
	base, err := url.Parse(address)
	if err != nil {
		return nil, errors.Wrap(err, "invalid URL")
	}

	// Obtain the public key from the URL's user.
	var pubkey *phase0.BLSPubKey
	if base.User != nil && base.User.Username() != "" {
		key := phase0.BLSPubKey{}
		data, err := hex.DecodeString(strings.TrimPrefix(base.User.Username(), "0x"))
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to parse public key %s", base.User.Username()))
		}
		copy(key[:], data)
		pubkey = &key

		// Remove the user from the URL.
		base.User = nil
	}
	s := &Service{
		base:         base,
		address:      base.String(),
		client:       client,
		timeout:      parameters.timeout,
		pubkey:       pubkey,
		extraHeaders: parameters.extraHeaders,
	}

	// Close the service on context done.
	go func(s *Service) {
		<-ctx.Done()
		log.Trace().Msg("Context done; closing connection")
		s.close()
	}(s)

	return s, nil
}

// Name provides the name of the service.
func (s *Service) Name() string {
	return s.address
}

// Address provides the address for the connection.
func (s *Service) Address() string {
	return s.address
}

// close closes the service, freeing up resources.
func (s *Service) close() {}

// Pubkey returns the public key of the builder (if any).
func (s *Service) Pubkey() *phase0.BLSPubKey {
	return s.pubkey
}

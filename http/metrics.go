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
	"context"
	"regexp"

	"github.com/attestantio/go-eth2-client/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	requestsCounter *prometheus.CounterVec
	requestsTimer   *prometheus.HistogramVec
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if requestsCounter != nil {
		// Already registered.
		return nil
	}
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}

	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	requestsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "builderclient",
		Subsystem: "http",
		Name:      "requests_total",
		Help:      "The number of builder requests.",
	}, []string{"server", "method", "endpoint", "result"})
	if err := prometheus.Register(requestsCounter); err != nil {
		return err
	}
	requestsTimer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "builderclient",
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "The time spent for successful builder requests.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	}, []string{"server", "method", "endpoint"})

	return prometheus.Register(requestsTimer)
}

func (s *Service) monitorGetComplete(_ context.Context, endpoint, result string) {
	if requestsCounter == nil {
		return
	}

	requestsCounter.WithLabelValues(s.address, "GET", reduceEndpoint(endpoint), result).Inc()
}

func (s *Service) monitorPostComplete(_ context.Context, endpoint, result string) {
	if requestsCounter == nil {
		return
	}

	requestsCounter.WithLabelValues(s.address, "POST", reduceEndpoint(endpoint), result).Inc()
}

type templateReplacement struct {
	pattern     *regexp.Regexp
	replacement []byte
}

var endpointTemplates = []*templateReplacement{
	{
		pattern:     regexp.MustCompile("/builder/header/[0-9]+/0x[0-9a-fA-F]{64}/0x[0-9a-fA-F]{96}"),
		replacement: []byte("/builder/header/{slot}/{parent_hash}/{pubkey}"),
	},
}

// reduceEndpoint reduces an endpoint to its template.
func reduceEndpoint(in string) string {
	out := []byte(in)
	for _, template := range endpointTemplates {
		out = template.pattern.ReplaceAll(out, template.replacement)
	}

	return string(out)
}

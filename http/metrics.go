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
	"time"

	"github.com/attestantio/go-eth2-client/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	operationsCounter *prometheus.CounterVec
	operationsTimer   *prometheus.HistogramVec
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if operationsCounter != nil {
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

// skipcq: RVV-B0012
func registerPrometheusMetrics(_ context.Context) error {
	operationsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "eth_builder_client",
		Subsystem: "operations",
		Name:      "total",
		Help:      "The number of builder operations.",
	}, []string{"server", "operation", "result"})
	if err := prometheus.Register(operationsCounter); err != nil {
		return err
	}
	operationsTimer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "eth_builder_client",
		Subsystem: "operations",
		Name:      "duration_seconds",
		Help:      "The time spent in builder operations.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	}, []string{"server", "operation"})
	return prometheus.Register(operationsTimer)
}

// monitorOperation monitors an operation.
func monitorOperation(server string, operation string, result string, duration time.Duration) {
	if operationsCounter == nil {
		// Not registered.
		return
	}

	operationsCounter.WithLabelValues(server, operation, result).Add(1)
	if result == "failed" {
		// We do not log timer for failures.
		return
	}

	operationsTimer.WithLabelValues(server, operation).Observe(duration.Seconds())
}

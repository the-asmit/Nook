// Package metrics creates the Prometheus registry each Nook binary exposes
// and the HTTP handler that serves it.
//
// A dedicated registry is used instead of the global default one so that no
// library can register metrics behind our back and tests stay isolated.
package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/the-asmit/nook/internal/version"
)

// Namespace prefixes every Nook metric name.
const Namespace = "nook"

// NewRegistry returns a registry pre-loaded with Go runtime and process
// metrics plus a nook_build_info gauge describing the running binary.
func NewRegistry(service string, info version.Info) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "build_info",
		Help:      "Build information of the running binary; the value is always 1.",
		ConstLabels: prometheus.Labels{
			"service":    service,
			"version":    info.Version,
			"commit":     info.Commit,
			"build_date": info.BuildDate,
			"go_version": info.GoVersion,
		},
	})
	buildInfo.Set(1)

	for _, c := range []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo,
	} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register collector: %w", err)
		}
	}
	return reg, nil
}

// Handler serves the registry in the Prometheus exposition format.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// Report scrape failures as a metric too, instead of only as an HTTP error.
		Registry: reg,
		// A broken collector should not hide every other metric.
		ErrorHandling: promhttp.ContinueOnError,
	})
}

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
}

func New() *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total HTTP requests",
			},

			[]string{
				"method",
				"path",
				"status",
			},
		),

		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_request_duration_seconds",
				Help: "HTTP latency",
			},

			[]string{
				"method",
				"path",
			},
		),
	}

	prometheus.MustRegister(m.RequestsTotal)
	prometheus.MustRegister(m.RequestDuration)

	return m
}

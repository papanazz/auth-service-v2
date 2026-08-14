package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec

	// AuthEventsTotal mirrors every audit.Event published anywhere in the
	// app layer — see platform/metrics.AuditPublisher, the decorator that
	// increments it. One counter covers all six endpoints instead of each
	// wiring its own: every use case already publishes an audit.Event for
	// its meaningful outcomes, so this piggybacks on that single
	// chokepoint rather than adding a metrics dependency to each service.
	//
	// Deliberately labeled by type/success only, not by audit.Event's
	// Reason field: several Reason values exist specifically to look
	// identical to a caller (e.g. login's unknown-account vs
	// wrong-password paths both return the same error) — a Prometheus
	// label is just as much an observable side channel as an HTTP
	// response body, and splitting on Reason would reopen exactly the
	// enumeration signal that design keeps closed. See docs/metrics.md.
	AuthEventsTotal *prometheus.CounterVec

	// RateLimitRejectionsTotal counts requests rejected by
	// platform/authattempt.RedisTracker, labeled by which limiter
	// tripped (e.g. "auth:login:ip", "auth:login:credential",
	// "auth:register:ip", "auth:resend-verification:ip" — the key's
	// prefix, never the IP/credential-hash suffix, which keeps
	// cardinality bounded to the fixed set of limiters that exist in
	// code). See docs/metrics.md for why this needs to exist alongside
	// the generic http_requests_total{status="429"}: login alone runs
	// two independent limiters (IP and credential+IP) behind the same
	// endpoint and the same 429, and telling "one IP hammering many
	// accounts" apart from "many IPs hammering one account" is a
	// different incident either way.
	RateLimitRejectionsTotal *prometheus.CounterVec
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

		AuthEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_events_total",
				Help: "Total audited authentication/account events, by type and outcome",
			},

			[]string{
				"type",
				"success",
			},
		),

		RateLimitRejectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_rate_limit_rejections_total",
				Help: "Total requests rejected by a rate limiter, by which limiter tripped",
			},

			[]string{
				"limiter",
			},
		),
	}

	prometheus.MustRegister(m.RequestsTotal)
	prometheus.MustRegister(m.RequestDuration)
	prometheus.MustRegister(m.AuthEventsTotal)
	prometheus.MustRegister(m.RateLimitRejectionsTotal)

	return m
}

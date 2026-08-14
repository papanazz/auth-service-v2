package metrics

import (
	"context"
	"strconv"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

var _ audit.Publisher = (*AuditPublisher)(nil)

// AuditPublisher decorates an audit.Publisher, recording AuthEventsTotal
// for every event before forwarding it. Every use case already publishes
// an audit.Event for its meaningful outcomes (LOGIN_SUCCESS, TOKEN_REUSE_
// DETECTED, EMAIL_VERIFIED, ...) — wrapping the single Publisher instance
// shared by all six endpoints (see app.go) gives every one of them a
// metric for free, with no change to any use case's constructor.
type AuditPublisher struct {
	next audit.Publisher

	metrics *Metrics
}

func NewAuditPublisher(
	next audit.Publisher,
	metrics *Metrics,
) *AuditPublisher {

	return &AuditPublisher{
		next: next,

		metrics: metrics,
	}
}

func (p *AuditPublisher) Publish(
	ctx context.Context,
	event audit.Event,
) error {

	// Recorded unconditionally, before forwarding: the metric's value is
	// operational visibility into what the app layer decided happened,
	// independent of whether the durable audit write behind it succeeds
	// — if anything, more important to have during a Postgres outage,
	// not less.
	p.metrics.AuthEventsTotal.
		WithLabelValues(
			string(event.Type),
			strconv.FormatBool(event.Success),
		).
		Inc()

	return p.next.Publish(ctx, event)
}

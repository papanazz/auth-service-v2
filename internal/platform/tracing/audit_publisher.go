package tracing

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

var _ audit.Publisher = (*AuditPublisher)(nil)

// AuditPublisher decorates an audit.Publisher, attaching each event's
// business identifiers to the span already active in ctx — the request's
// root span, started by middleware.Tracer before routing ever reaches a
// handler — before forwarding to the wrapped publisher.
//
// Without this, finding "which trace was this user's failed login" means
// going to the log backend first for a trace_id (logger.GetTraceID
// already ties every log line to one), then pasting that into Jaeger.
// This lets the same lookup happen directly in Jaeger's own search.
//
// Mirrors platform/metrics.AuditPublisher's shape deliberately, but kept
// as a separate decorator: one instruments Prometheus, the other OTel
// spans, and neither has any reason to know about the other. Both wrap
// the same shared audit.Publisher instance — see app.go.
type AuditPublisher struct {
	next audit.Publisher
}

func NewAuditPublisher(
	next audit.Publisher,
) *AuditPublisher {

	return &AuditPublisher{
		next: next,
	}
}

func (p *AuditPublisher) Publish(
	ctx context.Context,
	event audit.Event,
) error {

	span := trace.SpanFromContext(ctx)

	attrs := []attribute.KeyValue{

		attribute.String("event.type", string(event.Type)),

		attribute.Bool("event.success", event.Success),
	}

	if event.UserID != nil {

		attrs = append(
			attrs,
			attribute.String("user.id", event.UserID.String()),
		)
	}

	if event.SessionID != nil {

		attrs = append(
			attrs,
			attribute.String("session.id", event.SessionID.String()),
		)
	}

	span.SetAttributes(attrs...)

	return p.next.Publish(ctx, event)
}

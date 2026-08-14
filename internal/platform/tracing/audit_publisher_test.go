package tracing

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

type mockPublisher struct {
	published []audit.Event

	err error
}

func (m *mockPublisher) Publish(
	ctx context.Context,
	event audit.Event,
) error {

	m.published = append(m.published, event)

	return m.err
}

// startedSpan starts a real span against an in-memory exporter and
// returns a context carrying it, plus a finish func that ends the span
// and returns its exported attributes as a plain map. trace.SpanFromContext
// only finds a span if one was actually started against a
// TracerProvider — context.Background() alone would make SetAttributes a
// silent no-op and every assertion below would vacuously pass.
func startedSpan(t *testing.T) (
	context.Context,
	func() map[string]string,
) {

	t.Helper()

	exporter := tracetest.NewInMemoryExporter()

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)

	ctx, span :=
		tp.Tracer("test").
			Start(context.Background(), "test-span")

	return ctx, func() map[string]string {

		span.End()

		spans := exporter.GetSpans()

		if len(spans) != 1 {
			t.Fatalf("exported %d spans, want 1", len(spans))
		}

		got := map[string]string{}

		for _, kv := range spans[0].Attributes {
			got[string(kv.Key)] = kv.Value.String()
		}

		return got
	}
}

func TestAuditPublisher_Publish_SetsBusinessAttributesAndForwards(t *testing.T) {

	ctx, finish := startedSpan(t)

	next := &mockPublisher{}

	p := NewAuditPublisher(next)

	userID := uuid.New()

	sessionID := uuid.New()

	event := audit.New(audit.EventLoginSuccess)

	event.UserID = &userID

	event.SessionID = &sessionID

	event.Success = true

	if err := p.Publish(ctx, event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(next.published) != 1 {
		t.Fatalf("forwarded %d events, want 1", len(next.published))
	}

	if next.published[0].Type != audit.EventLoginSuccess {
		t.Errorf("forwarded event type = %q, want %q", next.published[0].Type, audit.EventLoginSuccess)
	}

	attrs := finish()

	if attrs["event.type"] != string(audit.EventLoginSuccess) {
		t.Errorf("event.type = %q, want %q", attrs["event.type"], audit.EventLoginSuccess)
	}

	if attrs["event.success"] != "true" {
		t.Errorf("event.success = %q, want %q", attrs["event.success"], "true")
	}

	if attrs["user.id"] != userID.String() {
		t.Errorf("user.id = %q, want %q", attrs["user.id"], userID.String())
	}

	if attrs["session.id"] != sessionID.String() {
		t.Errorf("session.id = %q, want %q", attrs["session.id"], sessionID.String())
	}
}

// login's own dummy-hash verification path (docs/login.md Capabilities)
// audits a failure with no UserID at all — an unknown account is exactly
// what that lookup failing means. The span must not carry a fabricated
// user.id in that case.
func TestAuditPublisher_Publish_OmitsUnknownIdentifiers(t *testing.T) {

	ctx, finish := startedSpan(t)

	p := NewAuditPublisher(&mockPublisher{})

	event := audit.New(audit.EventLoginFailed)

	event.Success = false

	if err := p.Publish(ctx, event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attrs := finish()

	if _, ok := attrs["user.id"]; ok {
		t.Errorf("user.id = %q, want it absent for an event with no UserID", attrs["user.id"])
	}

	if _, ok := attrs["session.id"]; ok {
		t.Errorf("session.id = %q, want it absent for an event with no SessionID", attrs["session.id"])
	}

	if attrs["event.type"] != string(audit.EventLoginFailed) {
		t.Errorf("event.type = %q, want %q", attrs["event.type"], audit.EventLoginFailed)
	}
}

// A request with no active span (tracing disabled, or a background job
// with no HTTP context) must not panic — trace.SpanFromContext falls back
// to a no-op span whose SetAttributes silently discards, which is exactly
// what should happen here.
func TestAuditPublisher_Publish_NoActiveSpanDoesNotPanic(t *testing.T) {

	next := &mockPublisher{}

	p := NewAuditPublisher(next)

	event := audit.New(audit.EventLogout)

	if err := p.Publish(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(next.published) != 1 {
		t.Fatalf("forwarded %d events, want 1", len(next.published))
	}
}

func TestAuditPublisher_Publish_PropagatesForwardingError(t *testing.T) {

	ctx, _ := startedSpan(t)

	next := &mockPublisher{err: errors.New("db unavailable")}

	p := NewAuditPublisher(next)

	err := p.Publish(ctx, audit.New(audit.EventLogout))

	if err == nil {
		t.Fatal("expected the next publisher's error to propagate")
	}
}

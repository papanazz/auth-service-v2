package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

// newTestMetrics builds a Metrics whose vectors are not registered against
// the global prometheus.DefaultRegisterer — metrics.New() does register
// there, and calling it more than once across a test binary panics on
// duplicate registration. Each test gets its own isolated counters instead.
func newTestMetrics() *Metrics {

	return &Metrics{

		AuthEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_auth_events_total",
			},

			[]string{"type", "success"},
		),

		RateLimitRejectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_rate_limit_rejections_total",
			},

			[]string{"limiter"},
		),
	}
}

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

func TestAuditPublisher_Publish_RecordsAndForwards(t *testing.T) {

	m := newTestMetrics()

	next := &mockPublisher{}

	p := NewAuditPublisher(next, m)

	event := audit.New(audit.EventLoginSuccess)

	event.Success = true

	if err := p.Publish(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(next.published) != 1 {
		t.Fatalf("forwarded %d events, want 1", len(next.published))
	}

	if next.published[0].Type != audit.EventLoginSuccess {
		t.Errorf("forwarded event type = %q, want %q", next.published[0].Type, audit.EventLoginSuccess)
	}

	got := testutil.ToFloat64(
		m.AuthEventsTotal.WithLabelValues(string(audit.EventLoginSuccess), "true"),
	)

	if got != 1 {
		t.Errorf("AuthEventsTotal{type=%q,success=true} = %v, want 1", audit.EventLoginSuccess, got)
	}
}

func TestAuditPublisher_Publish_LabelsFailureSeparately(t *testing.T) {

	m := newTestMetrics()

	p := NewAuditPublisher(&mockPublisher{}, m)

	event := audit.New(audit.EventLoginFailed)

	event.Success = false

	_ = p.Publish(context.Background(), event)

	successCount := testutil.ToFloat64(
		m.AuthEventsTotal.WithLabelValues(string(audit.EventLoginFailed), "true"),
	)

	failureCount := testutil.ToFloat64(
		m.AuthEventsTotal.WithLabelValues(string(audit.EventLoginFailed), "false"),
	)

	if successCount != 0 {
		t.Errorf("success-labeled count = %v, want 0", successCount)
	}

	if failureCount != 1 {
		t.Errorf("failure-labeled count = %v, want 1", failureCount)
	}
}

// The metric must reflect what the app layer decided happened even if the
// durable audit write behind it fails — the whole point is visibility
// that survives a Postgres outage, not one more thing that depends on it.
func TestAuditPublisher_Publish_RecordsEvenWhenNextFails(t *testing.T) {

	m := newTestMetrics()

	next := &mockPublisher{err: errors.New("db unavailable")}

	p := NewAuditPublisher(next, m)

	event := audit.New(audit.EventTokenReuseDetected)

	event.Success = false

	err := p.Publish(context.Background(), event)

	if err == nil {
		t.Fatal("expected the next publisher's error to propagate")
	}

	got := testutil.ToFloat64(
		m.AuthEventsTotal.WithLabelValues(string(audit.EventTokenReuseDetected), "false"),
	)

	if got != 1 {
		t.Errorf("AuthEventsTotal{type=TOKEN_REUSE_DETECTED,success=false} = %v, want 1 despite the forwarding error", got)
	}
}

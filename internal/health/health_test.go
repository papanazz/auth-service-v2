package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

type mockPinger struct {
	err error

	// block, if set, makes the check honor ctx instead of returning
	// immediately — used to prove Ready's timeout actually bounds a
	// hung dependency instead of waiting on it forever.
	block bool
}

func (m *mockPinger) ping(ctx context.Context) error {

	if m.block {

		<-ctx.Done()

		return ctx.Err()
	}

	return m.err
}

func (m *mockPinger) Ping(ctx context.Context) error {
	return m.ping(ctx)
}

func (m *mockPinger) Health(ctx context.Context) error {
	return m.ping(ctx)
}

func newTestLogger(t *testing.T) *logger.Logger {

	t.Helper()

	log, err := logger.New("test")

	if err != nil {
		t.Fatalf("failed to build test logger: %v", err)
	}

	return log
}

type readyBody struct {
	Data struct {
		Status string `json:"status"`

		Checks map[string]checkResult `json:"checks"`
	} `json:"data"`
}

func TestHandler_Health_IgnoresDependenciesEntirely(t *testing.T) {

	db := &mockPinger{err: errors.New("connection refused")}

	cache := &mockPinger{err: errors.New("connection refused")}

	h := NewHandler(newTestLogger(t), db, cache)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	rec := httptest.NewRecorder()

	h.Health(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — liveness must not depend on Postgres/Redis", rec.Code, http.StatusOK)
	}
}

func TestHandler_Ready_AllDependenciesHealthy(t *testing.T) {

	h := NewHandler(newTestLogger(t), &mockPinger{}, &mockPinger{})

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	rec := httptest.NewRecorder()

	h.Ready(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body readyBody

	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Data.Status != "ready" {
		t.Errorf("status = %q, want %q", body.Data.Status, "ready")
	}

	for _, name := range []string{"database", "redis"} {

		if body.Data.Checks[name].Status != "ok" {
			t.Errorf("checks[%q].status = %q, want %q", name, body.Data.Checks[name].Status, "ok")
		}
	}
}

func TestHandler_Ready_DatabaseDown(t *testing.T) {

	h := NewHandler(
		newTestLogger(t),
		&mockPinger{err: errors.New("dial tcp: connection refused")},
		&mockPinger{},
	)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	rec := httptest.NewRecorder()

	h.Ready(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body readyBody

	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body.Data.Status != "not_ready" {
		t.Errorf("status = %q, want %q", body.Data.Status, "not_ready")
	}

	if body.Data.Checks["database"].Status != "error" {
		t.Errorf(`checks["database"].status = %q, want "error"`, body.Data.Checks["database"].Status)
	}

	if body.Data.Checks["redis"].Status != "ok" {
		t.Errorf(`checks["redis"].status = %q, want "ok" — one dependency failing must not mask the other's real status`, body.Data.Checks["redis"].Status)
	}

	// The raw error text must never reach the response body — only the
	// generic "error" status. Anyone can reach this endpoint; the real
	// message (which can include hostnames) goes to the logger instead.
	if body.Data.Checks["database"].Status == "connection refused" {
		t.Error("raw error text leaked into the response body")
	}
}

func TestHandler_Ready_RedisDown(t *testing.T) {

	h := NewHandler(
		newTestLogger(t),
		&mockPinger{},
		&mockPinger{err: errors.New("NOAUTH Authentication required")},
	)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	rec := httptest.NewRecorder()

	h.Ready(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body readyBody

	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body.Data.Checks["redis"].Status != "error" {
		t.Errorf(`checks["redis"].status = %q, want "error"`, body.Data.Checks["redis"].Status)
	}

	if body.Data.Checks["database"].Status != "ok" {
		t.Errorf(`checks["database"].status = %q, want "ok"`, body.Data.Checks["database"].Status)
	}
}

// A dependency that never responds must not hang the endpoint forever —
// Ready's own internal timeout has to fire and report the check as
// failed, not leave the HTTP response pending indefinitely.
func TestHandler_Ready_HungDependencyTimesOut(t *testing.T) {

	h := NewHandler(newTestLogger(t), &mockPinger{block: true}, &mockPinger{})

	h.timeout = 50 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	rec := httptest.NewRecorder()

	done := make(chan struct{})

	go func() {
		h.Ready(rec, req)
		close(done)
	}()

	select {

	case <-done:

	case <-time.After(time.Second):
		t.Fatal("Ready did not return within 1s of a 50ms dependency timeout")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

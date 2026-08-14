package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/idempotency"
)

func TestMain(m *testing.M) {

	// Real production values would make the timeout and concurrency tests
	// below run at wall-clock speed for no benefit.
	pollInterval = 5 * time.Millisecond
	maxWait = 200 * time.Millisecond

	os.Exit(m.Run())
}

// fakeStore mirrors the real Redis-backed Store's claim-or-peek semantics —
// GET-or-SET as one atomic step, Save overwrites, Release deletes — closely
// enough to exercise the middleware's control flow, including genuine
// concurrent claim races, without a real Redis.
type fakeStore struct {
	mu sync.Mutex

	records map[string]*idempotency.Record

	claimErr error

	saveCalls []idempotency.Record

	releaseCalls []string
}

func newFakeStore() *fakeStore {

	return &fakeStore{
		records: map[string]*idempotency.Record{},
	}
}

func (f *fakeStore) TryClaim(
	ctx context.Context,
	key string,
	requestHash string,
	reservationTTL time.Duration,
) (bool, *idempotency.Record, error) {

	if f.claimErr != nil {
		return false, nil, f.claimErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if existing, ok := f.records[key]; ok {

		cp := *existing

		return false, &cp, nil
	}

	f.records[key] = &idempotency.Record{RequestHash: requestHash}

	return true, nil, nil
}

func (f *fakeStore) Save(
	ctx context.Context,
	key string,
	record idempotency.Record,
	ttl time.Duration,
) error {

	f.mu.Lock()
	defer f.mu.Unlock()

	f.saveCalls = append(f.saveCalls, record)

	cp := record

	f.records[key] = &cp

	return nil
}

func (f *fakeStore) Release(
	ctx context.Context,
	key string,
) error {

	f.mu.Lock()
	defer f.mu.Unlock()

	f.releaseCalls = append(f.releaseCalls, key)

	delete(f.records, key)

	return nil
}

func okHandler(body string) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

func doRequest(
	t *testing.T,
	h http.Handler,
	key string,
	body string,
) *httptest.ResponseRecorder {

	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))

	if key != "" {
		req.Header.Set(idempotencyHeader, key)
	}

	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	return rec
}

func TestIdempotency_NoKeyIsRejectedWhenRequired(t *testing.T) {

	store := newFakeStore()

	var calls int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	})

	rec := doRequest(t, Idempotency(store, time.Minute, true)(handler), "", `{}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "IDEMPOTENCY_KEY_REQUIRED") {
		t.Errorf("body = %q, want the IDEMPOTENCY_KEY_REQUIRED code", rec.Body.String())
	}

	if calls != 0 {
		t.Errorf("handler called %d times, want 0 — a missing required key must not reach it", calls)
	}
}

func TestIdempotency_NoKeyPassesThroughWhenNotRequired(t *testing.T) {

	store := newFakeStore()

	var calls int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	})

	rec := doRequest(t, Idempotency(store, time.Minute, false)(handler), "", `{}`)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}

	if len(store.saveCalls) != 0 {
		t.Errorf("store.Save called %d times, want 0 — no key means no caching", len(store.saveCalls))
	}
}

func TestIdempotency_FirstRequestExecutesAndCaches(t *testing.T) {

	store := newFakeStore()

	rec := doRequest(t, Idempotency(store, time.Minute, true)(okHandler(`{"ok":true}`)), "key-1", `{"a":1}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q, want the handler's response", rec.Body.String())
	}

	if rec.Header().Get("Idempotency-Replayed") != "" {
		t.Error("the original request must not be marked as a replay")
	}

	if len(store.saveCalls) != 1 {
		t.Fatalf("store.Save called %d times, want 1", len(store.saveCalls))
	}

	if store.saveCalls[0].Status != http.StatusOK {
		t.Errorf("cached status = %d, want 200", store.saveCalls[0].Status)
	}

	if string(store.saveCalls[0].Body) != `{"ok":true}` {
		t.Errorf("cached body = %q, want the handler's response", store.saveCalls[0].Body)
	}
}

func TestIdempotency_ServerErrorIsNotCached(t *testing.T) {

	store := newFakeStore()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})

	rec := doRequest(t, Idempotency(store, time.Minute, true)(handler), "key-1", `{}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	if len(store.saveCalls) != 0 {
		t.Errorf("store.Save called %d times, want 0 — a 500 must not be cached", len(store.saveCalls))
	}

	if len(store.releaseCalls) != 1 {
		t.Errorf("store.Release called %d times, want 1 — the reservation must be freed for a real retry", len(store.releaseCalls))
	}
}

func TestIdempotency_ReplaysACompletedRecordWithoutCallingTheHandler(t *testing.T) {

	store := newFakeStore()

	handler := Idempotency(store, time.Minute, true)(okHandler(`{"ok":true}`))

	first := doRequest(t, handler, "key-1", `{"a":1}`)

	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}

	var calls int32

	countingHandler := Idempotency(store, time.Minute, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTeapot)
	}))

	second := doRequest(t, countingHandler, "key-1", `{"a":1}`)

	if calls != 0 {
		t.Errorf("handler called %d times on replay, want 0", calls)
	}

	if second.Code != http.StatusOK {
		t.Errorf("replayed status = %d, want the original 200", second.Code)
	}

	if second.Body.String() != `{"ok":true}` {
		t.Errorf("replayed body = %q, want the original response", second.Body.String())
	}

	if second.Header().Get("Idempotency-Replayed") != "true" {
		t.Error("a replayed response must be marked as such")
	}
}

func TestIdempotency_SameKeyDifferentBodyIsAConflict(t *testing.T) {

	store := newFakeStore()

	handler := Idempotency(store, time.Minute, true)(okHandler(`{"ok":true}`))

	if rec := doRequest(t, handler, "key-1", `{"a":1}`); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}

	second := doRequest(t, handler, "key-1", `{"a":2}`)

	if second.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 for a reused key with a different body", second.Code)
	}

	if !strings.Contains(second.Body.String(), "IDEMPOTENCY_KEY_CONFLICT") {
		t.Errorf("body = %q, want the IDEMPOTENCY_KEY_CONFLICT code", second.Body.String())
	}
}

func TestIdempotency_StillInProgressAfterMaxWaitReturns409(t *testing.T) {

	store := newFakeStore()

	// Claim the key and never complete it, simulating a stuck or still-running
	// original request.
	store.records["idem:/v1/auth/login:key-1"] = &idempotency.Record{RequestHash: hashRequest([]byte(`{}`))}

	rec := doRequest(t, Idempotency(store, time.Minute, true)(okHandler(`{}`)), "key-1", `{}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "IDEMPOTENCY_KEY_IN_PROGRESS") {
		t.Errorf("body = %q, want the IDEMPOTENCY_KEY_IN_PROGRESS code", rec.Body.String())
	}

	if rec.Header().Get("Retry-After") == "" {
		t.Error("a still-in-progress response should hint the client to retry")
	}
}

func TestIdempotency_WaiterPicksUpTheWinnersResultOnceItCompletes(t *testing.T) {

	store := newFakeStore()

	store.records["idem:/v1/auth/login:key-1"] = &idempotency.Record{RequestHash: hashRequest([]byte(`{}`))}

	// The "winner" finishes shortly after the waiter starts polling — well
	// inside maxWait, but after at least one poll tick.
	go func() {
		time.Sleep(3 * pollInterval)

		_ = store.Save(
			context.Background(),
			"idem:/v1/auth/login:key-1",
			idempotency.Record{Status: http.StatusOK, Body: []byte(`{"ok":true}`), RequestHash: hashRequest([]byte(`{}`))},
			time.Minute,
		)
	}()

	rec := doRequest(t, Idempotency(store, time.Minute, true)(okHandler(`{}`)), "key-1", `{}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 once the winner's result appears", rec.Code)
	}

	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q, want the winner's cached response", rec.Body.String())
	}
}

func TestIdempotency_StoreErrorDegradesToUnprotectedExecution(t *testing.T) {

	store := newFakeStore()

	store.claimErr = errors.New("redis unreachable")

	var calls int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	})

	rec := doRequest(t, Idempotency(store, time.Minute, true)(handler), "key-1", `{}`)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — a store outage must not fail the request", rec.Code)
	}

	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}

// The centerpiece: N callers racing with the identical key. Exactly one must
// execute the handler; every other caller must replay that one's result
// rather than running the handler itself or timing out.
func TestIdempotency_ConcurrentIdenticalRequestsExecuteOnce(t *testing.T) {

	const clients = 20

	store := newFakeStore()

	var calls int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		n := atomic.AddInt32(&calls, 1)

		// Widen the race window so concurrent callers genuinely land in the
		// poll loop instead of the claim always resolving before the next
		// goroutine even starts.
		time.Sleep(10 * pollInterval)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"call":` + strconv.Itoa(int(n)) + `}`))
	})

	wrapped := Idempotency(store, time.Minute, true)(handler)

	var (
		wg sync.WaitGroup

		mu sync.Mutex

		bodies []string

		codes []int
	)

	start := make(chan struct{})

	for i := 0; i < clients; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			rec := doRequest(t, wrapped, "race-key", `{"a":1}`)

			mu.Lock()
			bodies = append(bodies, rec.Body.String())
			codes = append(codes, rec.Code)
			mu.Unlock()
		}()
	}

	close(start)
	wg.Wait()

	if calls != 1 {
		t.Fatalf("handler executed %d times, want exactly 1", calls)
	}

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("caller %d: status = %d, want 200", i, code)
		}
	}

	first := bodies[0]

	for i, b := range bodies {
		if b != first {
			t.Errorf("caller %d body = %q, want %q (every caller must see the same, single execution's result)", i, b, first)
		}
	}

	if len(store.saveCalls) != 1 {
		t.Errorf("store.Save called %d times, want 1", len(store.saveCalls))
	}
}

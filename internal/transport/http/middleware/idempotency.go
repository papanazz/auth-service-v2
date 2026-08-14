package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/idempotency"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

const (
	idempotencyHeader = "Idempotency-Key"

	// reservationTTL bounds how long a claim may sit unresolved — a crashed
	// or hung request — before the key is considered abandoned and the next
	// caller may claim it fresh. Generous relative to how long a login
	// should ever take, tight enough not to wedge a key for long.
	reservationTTL = 30 * time.Second
)

// pollInterval and maxWait bound how long a caller that lost the claim race
// waits for the winner to finish, comfortably inside the server's own
// request timeout so callers get a clear 409 instead of a generic timeout.
// Variables, not constants, so tests can shrink them instead of running at
// real time.
var (
	pollInterval = 150 * time.Millisecond

	maxWait = 3 * time.Second
)

// IdempotencyStore is the narrow slice of idempotency.Store this middleware
// needs, declared here so tests can substitute a fake instead of Redis.
type IdempotencyStore interface {
	TryClaim(
		ctx context.Context,
		key string,
		requestHash string,
		reservationTTL time.Duration,
	) (claimed bool, existing *idempotency.Record, err error)

	Save(
		ctx context.Context,
		key string,
		record idempotency.Record,
		ttl time.Duration,
	) error

	Release(
		ctx context.Context,
		key string,
	) error
}

// Idempotency makes a POST endpoint safe to retry: a request replayed with
// the same Idempotency-Key header gets back the exact response the first
// attempt produced, without the handler running again. Requests without the
// header are unaffected — the header is opt-in, matching how Stripe and AWS
// treat it.
//
// Only successful and client-error responses are cached. A 5xx is released
// instead, so a transient failure (a dependency blip, not the request
// itself) doesn't poison every retry for the rest of the TTL window.
//
// If the store errors — Redis is unreachable — the request runs unprotected
// rather than failing outright: idempotency here is a reliability nicety,
// not a security control, so degrading gracefully beats an availability
// outage caused by the safety net itself. Contrast with the login rate
// limiter, which fails closed because letting requests through unchecked
// there would defeat its purpose.
func Idempotency(
	store IdempotencyStore,
	ttl time.Duration,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {

				clientKey := r.Header.Get(idempotencyHeader)

				if clientKey == "" {

					next.ServeHTTP(w, r)

					return
				}

				// Namespaced by route and prefixed so a client-supplied key can
				// never collide with another key pattern in this Redis instance
				// (e.g. the login rate limiter's auth:login:* keys).
				key := "idem:" + r.URL.Path + ":" + clientKey

				body, err :=
					io.ReadAll(
						r.Body,
					)

				if err != nil {

					response.WriteError(
						w,
						errs.ErrInvalidRequest,
					)

					return
				}

				r.Body =
					io.NopCloser(
						bytes.NewReader(body),
					)

				requestHash := hashRequest(body)

				deadline :=
					time.Now().Add(maxWait)

				for {

					claimed, existing, err :=
						store.TryClaim(
							r.Context(),
							key,
							requestHash,
							reservationTTL,
						)

					if err != nil {

						next.ServeHTTP(w, r)

						return
					}

					if claimed {

						runAndSave(
							next,
							store,
							w,
							r,
							key,
							requestHash,
							ttl,
						)

						return
					}

					if existing.RequestHash != requestHash {

						response.WriteError(
							w,
							errs.ErrIdempotencyKeyConflict,
						)

						return
					}

					if !existing.InProgress() {

						replay(w, existing)

						return
					}

					if time.Now().After(deadline) {

						w.Header().Set(
							"Retry-After",
							"1",
						)

						response.WriteError(
							w,
							errs.ErrIdempotencyKeyInProgress,
						)

						return
					}

					select {

					case <-time.After(pollInterval):

					case <-r.Context().Done():

						return
					}
				}
			},
		)
	}
}

func runAndSave(
	next http.Handler,
	store IdempotencyStore,
	w http.ResponseWriter,
	r *http.Request,
	key string,
	requestHash string,
	ttl time.Duration,
) {

	capture :=
		&captureWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
			body:           &bytes.Buffer{},
		}

	next.ServeHTTP(capture, r)

	// Flush the real response to the client first — caching must never be
	// the reason a caller doesn't get their answer.
	w.WriteHeader(capture.status)

	_, _ = w.Write(capture.body.Bytes())

	if capture.status >= http.StatusInternalServerError {

		_ =
			store.Release(
				r.Context(),
				key,
			)

		return
	}

	_ =
		store.Save(
			r.Context(),
			key,
			idempotency.Record{

				Status: capture.status,

				Body: capture.body.Bytes(),

				RequestHash: requestHash,
			},
			ttl,
		)
}

func replay(
	w http.ResponseWriter,
	record *idempotency.Record,
) {

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.Header().Set(
		"Idempotency-Replayed",
		"true",
	)

	w.WriteHeader(record.Status)

	_, _ = w.Write(record.Body)
}

func hashRequest(body []byte) string {

	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}

// captureWriter buffers the response instead of streaming it straight
// through, so the full status and body are known and can be cached once the
// handler finishes.
type captureWriter struct {
	http.ResponseWriter

	status int

	body *bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
}

func (c *captureWriter) Write(b []byte) (int, error) {
	return c.body.Write(b)
}

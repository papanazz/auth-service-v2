package health

import (
	"context"
	"net/http"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

// DatabasePinger is satisfied by *pgxpool.Pool.
type DatabasePinger interface {
	Ping(ctx context.Context) error
}

// CachePinger is satisfied by *redis.Cache.
type CachePinger interface {
	Health(ctx context.Context) error
}

type Handler struct {
	logger *logger.Logger

	db DatabasePinger

	cache CachePinger

	timeout time.Duration
}

func NewHandler(
	log *logger.Logger,
	db DatabasePinger,
	cache CachePinger,
) *Handler {

	return &Handler{
		logger: log,

		db: db,

		cache: cache,

		timeout: 2 * time.Second,
	}
}

// Health is a liveness check: it answers "is this process able to
// respond to a request at all," nothing more. Deliberately makes no
// calls to Postgres or Redis — see docs/health.md Decisions for why
// tying liveness to a downstream dependency is the wrong call.
func (h *Handler) Health(
	w http.ResponseWriter,
	r *http.Request,
) {

	response.WriteJSON(
		w,
		http.StatusOK,
		map[string]string{
			"status": "ok",
		},
	)
}

type checkResult struct {
	Status string `json:"status"`

	DurationMS int64 `json:"duration_ms"`
}

// Ready is a readiness check: it answers "can this instance currently
// serve traffic correctly," which means actually reaching Postgres and
// Redis. A 503 here is what should pull an instance out of
// load-balancer rotation without killing it — see docs/health.md.
func (h *Handler) Ready(
	w http.ResponseWriter,
	r *http.Request,
) {

	ctx, cancel :=
		context.WithTimeout(
			r.Context(),
			h.timeout,
		)

	defer cancel()

	type outcome struct {
		name string

		err error

		took time.Duration
	}

	results := make(chan outcome, 2)

	check := func(
		name string,
		fn func(context.Context) error,
	) {

		start := time.Now()

		err := fn(ctx)

		results <- outcome{
			name: name,

			err: err,

			took: time.Since(start),
		}
	}

	go check("database", h.db.Ping)

	go check("redis", h.cache.Health)

	checks := make(map[string]checkResult, 2)

	ready := true

	for range 2 {

		result := <-results

		status := "ok"

		if result.err != nil {

			status = "error"

			ready = false

			// The raw error (which can include hostnames/ports) is
			// logged server-side, never put in the response body —
			// this endpoint has no auth in front of it today, same as
			// /metrics (docs/metrics.md Gaps).
			h.logger.Error(
				r.Context(),
				"[Ready] dependency check failed",
				result.err,
				logger.Metadata{
					"dependency": result.name,
				},
			)
		}

		checks[result.name] = checkResult{
			Status: status,

			DurationMS: result.took.Milliseconds(),
		}
	}

	status := http.StatusOK

	overall := "ready"

	if !ready {

		status = http.StatusServiceUnavailable

		overall = "not_ready"
	}

	response.WriteJSON(
		w,
		status,
		map[string]any{
			"status": overall,

			"checks": checks,
		},
	)
}

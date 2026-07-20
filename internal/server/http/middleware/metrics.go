package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
)

func Metrics(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()

				rw := &responseWriter{
					ResponseWriter: w,
					status:         200,
				}

				next.ServeHTTP(rw, r)

				duration := time.Since(start).Seconds()

				m.RequestsTotal.
					WithLabelValues(
						r.Method,
						r.URL.Path,
						strconv.Itoa(
							rw.status,
						),
					).
					Inc()

				m.RequestDuration.
					WithLabelValues(
						r.Method,
						r.URL.Path,
					).
					Observe(
						duration,
					)
			},
		)
	}
}

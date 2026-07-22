package middleware

import (
	"net/http"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func Logger(logger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()

				rw := &responseWriter{
					ResponseWriter: w,
					status:         http.StatusOK,
				}

				next.ServeHTTP(rw, r)

				if r.URL.Path != "/metrics" && r.URL.Path != "/health" {
					logger.Info(
						r.Context(),
						"http_request",
						map[string]any{
							"method":    r.Method,
							"path":      r.URL.Path,
							"status":    rw.status,
							"duration":  time.Since(start),
							"remote_ip": r.RemoteAddr,
						},
					)
				}
			},
		)
	}
}

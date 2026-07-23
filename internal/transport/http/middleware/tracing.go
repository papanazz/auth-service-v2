package middleware

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func Tracer(serviceName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := otelhttp.NewHandler(
			next,
			serviceName,
			otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
				if rc := chi.RouteContext(r.Context()); rc != nil {
					if pattern := rc.RoutePattern(); pattern != "" {
						return r.Method + " " + pattern
					}
				}

				return r.Method + " " + r.URL.Path
			}),
			otelhttp.WithFilter(func(r *http.Request) bool {
				return r.URL.Path != "/metrics"
			}),
		)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			span := trace.SpanFromContext(r.Context())

			requestID, ok := r.Context().Value("request_id").(string)
			if ok {
				span.SetAttributes(
					attribute.String("request.id", requestID),
				)
			}

			handler.ServeHTTP(w, r)
		})
	}
}

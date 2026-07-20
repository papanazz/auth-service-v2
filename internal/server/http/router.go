package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/papanazz/auth-service-v2/internal/app"
	"github.com/papanazz/auth-service-v2/internal/health"
	"github.com/papanazz/auth-service-v2/internal/server/http/middleware"
)

func NewRouter(
	application *app.Application,
) http.Handler {

	r := chi.NewRouter()

	r.Use(
		middleware.Recovery,
		middleware.RequestID,
		middleware.Tracer("auth-service"),
		middleware.Metrics(application.Metrics),
		middleware.Logger(application.Logger),
	)

	// Metrics Endpoint
	r.Handle(
		"/metrics",
		promhttp.Handler(),
	)

	healthHandler := health.NewHandler()

	r.Get(
		"/health",
		healthHandler.Health,
	)

	return r
}

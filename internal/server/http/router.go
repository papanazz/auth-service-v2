package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/papanazz/auth-service-v2/internal/app"
	"github.com/papanazz/auth-service-v2/internal/health"
	"github.com/papanazz/auth-service-v2/internal/server/http/handler"
	"github.com/papanazz/auth-service-v2/internal/server/http/middleware"
)

func NewRouter(
	application *app.Application,
) http.Handler {

	r := chi.NewRouter()

	r.Use(
		middleware.Recovery,
		middleware.Timeout(5*time.Second),
		middleware.RequestID,
		middleware.Tracer(application.Config.AppName),
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

	authHandler := handler.NewAuthHandler(
		application.RegisterService,
	)

	r.Post(
		"/v1/auth/register",
		authHandler.Register,
	)

	return r
}

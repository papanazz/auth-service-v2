package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/papanazz/auth-service-v2/internal/app"
	"github.com/papanazz/auth-service-v2/internal/health"
	"github.com/papanazz/auth-service-v2/internal/transport/http/handler"
	"github.com/papanazz/auth-service-v2/internal/transport/http/middleware"
)

func NewRouter(
	application *app.Application,
) http.Handler {

	r := chi.NewRouter()

	r.Use(
		middleware.Recovery,
		middleware.Timeout(5*time.Second),
		middleware.RequestID,
		middleware.Tracer(application.Config.App.Name),
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

	userHandler := handler.NewUserHandler(application.Logger, application.RegisterService)

	r.Post(
		"/v1/user/register",
		userHandler.Register,
	)

	authHandler := handler.NewAuthHandler(application.Logger, application.LoginService)

	r.With(
		middleware.Idempotency(
			application.IdempotencyStore,
			application.Config.Idempotency.TTL,
			true,
		),
	).Post(
		"/v1/auth/login",
		authHandler.Login,
	)

	refreshHandler := handler.NewRefreshHandler(application.Logger, application.RefreshService)

	r.Post(
		"/v1/auth/refresh",
		refreshHandler.Handle,
	)

	logoutHandler := handler.NewLogoutHandler(application.Logger, application.LogoutService)

	r.Post(
		"/v1/auth/logout",
		logoutHandler.Handle,
	)

	return r
}

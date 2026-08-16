package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/papanazz/auth-service-v2/internal/app/auth/oauthcallback"
	"github.com/papanazz/auth-service-v2/internal/app/auth/oauthstart"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

// providerGoogle is the only value {provider} currently accepts
// (docs/oauth.md) — a plain string, not domain/oauth.Provider, since
// this is a URL path segment comparison, not anything that touches
// account-linking policy.
const providerGoogle = "google"

type OAuthHandler struct {
	logger *logger.Logger

	start *oauthstart.Service

	callback *oauthcallback.Service
}

func NewOAuthHandler(
	logger *logger.Logger,
	start *oauthstart.Service,
	callback *oauthcallback.Service,
) *OAuthHandler {

	return &OAuthHandler{
		logger: logger,

		start: start,

		callback: callback,
	}
}

func (h *OAuthHandler) Start(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	if !strings.EqualFold(chi.URLParam(r, "provider"), providerGoogle) {

		response.WriteError(w, errs.ErrOAuthProviderUnsupported)

		return
	}

	query := r.URL.Query()

	result, err :=
		h.start.Handle(
			ctx,
			oauthstart.Command{

				DeviceID: query.Get("device_id"),

				DeviceName: query.Get("device_name"),

				DeviceType: session.DeviceType(query.Get("device_type")),
			},
		)

	if err != nil {

		response.LogAndWriteError(w, ctx, h.logger, "OAuthStart", err, logger.Metadata{
			"device_id":   query.Get("device_id"),
			"device_type": query.Get("device_type"),
		})

		return
	}

	response.WriteJSON(
		w,
		http.StatusOK,
		result,
	)
}

func (h *OAuthHandler) Callback(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	if !strings.EqualFold(chi.URLParam(r, "provider"), providerGoogle) {

		response.WriteError(w, errs.ErrOAuthProviderUnsupported)

		return
	}

	query := r.URL.Query()

	result, err :=
		h.callback.Handle(
			ctx,
			oauthcallback.Command{

				Code: query.Get("code"),

				State: query.Get("state"),

				IPAddress: r.RemoteAddr,

				UserAgent: r.UserAgent(),
			},
		)

	if err != nil {

		// Neither code nor state is logged — code is a one-time bearer
		// credential for the provider exchange and state is a CSRF
		// token, the same "never log a credential" stance the rest of
		// this package already takes on refresh tokens and verification
		// tokens (docs/logging.md).
		response.LogAndWriteError(w, ctx, h.logger, "OAuthCallback", err, nil)

		return
	}

	response.WriteJSON(
		w,
		http.StatusOK,
		result,
	)
}

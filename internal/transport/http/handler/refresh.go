package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/auth/refresh"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type RefreshHandler struct {
	logger  *logger.Logger
	service *refresh.Service
}

func NewRefreshHandler(
	logger *logger.Logger,
	service *refresh.Service,
) *RefreshHandler {

	return &RefreshHandler{
		logger:  logger,
		service: service,
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *RefreshHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req refreshRequest

	if err :=
		json.NewDecoder(
			r.Body,
		).
			Decode(
				&req,
			); err != nil {

		h.logger.Warn(ctx, "[Refresh] malformed request body", logger.Metadata{
			"error": err.Error(),
		})

		response.WriteError(
			w,
			errs.ErrInvalidRequest,
		)

		return
	}

	result, err :=
		h.service.Handle(
			ctx,
			refresh.Command{

				RefreshToken: req.RefreshToken,

				IPAddress: r.RemoteAddr,

				UserAgent: r.UserAgent(),
			},
		)

	if err != nil {

		// The refresh token itself is never logged, masked or not —
		// it's a bearer credential, the same class as a password. No
		// user/session identifier is available at this layer on
		// failure (only the service, past the point of failure, ever
		// resolves one) — see docs/logging.md.
		response.LogAndWriteError(w, ctx, h.logger, "Refresh", err, logger.Metadata{
			"user_agent": r.UserAgent(),
		})

		return
	}

	response.WriteJSON(
		w,
		http.StatusOK,
		result,
	)
}

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/auth/logout"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type LogoutHandler struct {
	logger  *logger.Logger
	service *logout.Service
}

func NewLogoutHandler(
	logger *logger.Logger,
	service *logout.Service,
) *LogoutHandler {

	return &LogoutHandler{
		logger:  logger,
		service: service,
	}
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *LogoutHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req logoutRequest

	if err :=
		json.NewDecoder(
			r.Body,
		).
			Decode(
				&req,
			); err != nil {

		response.WriteError(
			w,
			errs.ErrInvalidRequest,
		)

		return
	}

	err :=
		h.service.Handle(
			ctx,
			logout.Command{

				RefreshToken: req.RefreshToken,

				IPAddress: r.RemoteAddr,

				UserAgent: r.UserAgent(),
			},
		)

	if err != nil {
		h.logger.Error(ctx, "[Logout] Got error from service", err, nil)
		response.WriteError(
			w,
			err,
		)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

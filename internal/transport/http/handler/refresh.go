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
			},
		)

	if err != nil {
		h.logger.Error(ctx, "[Refresh] Got error from service", err, nil)
		response.WriteError(
			w,
			err,
		)

		return
	}

	response.WriteJSON(
		w,
		http.StatusOK,
		result,
	)
}

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/auth/refresh"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type RefreshHandler struct {
	service *refresh.Service
}

func NewRefreshHandler(
	service *refresh.Service,
) *RefreshHandler {

	return &RefreshHandler{
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
			r.Context(),
			refresh.Command{

				RefreshToken: req.RefreshToken,
			},
		)

	if err != nil {

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

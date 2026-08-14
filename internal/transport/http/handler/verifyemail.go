package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/user/verifyemail"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type VerifyEmailHandler struct {
	logger  *logger.Logger
	service *verifyemail.Service
}

func NewVerifyEmailHandler(
	logger *logger.Logger,
	service *verifyemail.Service,
) *VerifyEmailHandler {

	return &VerifyEmailHandler{
		logger:  logger,
		service: service,
	}
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (h *VerifyEmailHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req verifyEmailRequest

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
			verifyemail.Command{

				Token: req.Token,

				IPAddress: r.RemoteAddr,

				UserAgent: r.UserAgent(),
			},
		)

	if err != nil {
		h.logger.Error(ctx, "[VerifyEmail] Got error from service", err, nil)
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

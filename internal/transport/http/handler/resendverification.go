package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/user/resendverification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type ResendVerificationHandler struct {
	logger  *logger.Logger
	service *resendverification.Service
}

func NewResendVerificationHandler(
	logger *logger.Logger,
	service *resendverification.Service,
) *ResendVerificationHandler {

	return &ResendVerificationHandler{
		logger:  logger,
		service: service,
	}
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

func (h *ResendVerificationHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req resendVerificationRequest

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
			resendverification.Command{

				Email: req.Email,

				IPAddress: r.RemoteAddr,

				UserAgent: r.UserAgent(),
			},
		)

	if err != nil {
		h.logger.Error(ctx, "[ResendVerification] Got error from service", err, nil)
		response.WriteError(
			w,
			err,
		)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

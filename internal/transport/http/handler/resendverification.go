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

		h.logger.Warn(ctx, "[ResendVerification] malformed request body", logger.Metadata{
			"error": err.Error(),
		})

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

		// This only fires for a genuine failure (rate limited, infra
		// error) — the unknown-email/already-verified no-op paths
		// return nil from the service and never reach here, so logging
		// the (masked) email on an actual error doesn't reopen the
		// enumeration-safety the 204 response already guarantees
		// (docs/email-verification.md Decisions).
		response.LogAndWriteError(w, ctx, h.logger, "ResendVerification", err, logger.Metadata{
			"email":      logger.MaskEmail(req.Email),
			"user_agent": r.UserAgent(),
		})

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

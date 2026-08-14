package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type UserHandler struct {
	logger   *logger.Logger
	register *register.RegisterService
}

func NewUserHandler(
	logger *logger.Logger,
	register *register.RegisterService,
) *UserHandler {
	return &UserHandler{
		logger:   logger,
		register: register,
	}
}

func (h *UserHandler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {

		h.logger.Warn(ctx, "[Register] malformed request body", logger.Metadata{
			"error": err.Error(),
		})

		response.WriteError(w, errs.ErrInvalidRequest)
		return
	}

	res, err := h.register.Handle(
		ctx,
		register.Command{
			Email:     req.Email,
			Password:  req.Password,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
		},
	)

	if err != nil {

		response.LogAndWriteError(w, ctx, h.logger, "Register", err, logger.Metadata{
			"email":      logger.MaskEmail(req.Email),
			"user_agent": r.UserAgent(),
		})

		return
	}

	response.WriteJSON(
		w,
		http.StatusCreated,
		res,
	)
}

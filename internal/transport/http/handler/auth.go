package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/transport/http/response"
)

type AuthHandler struct {
	logger *logger.Logger
	login  *login.LoginService
}

func NewAuthHandler(
	logger *logger.Logger,
	login *login.LoginService,
) *AuthHandler {
	return &AuthHandler{
		logger: logger,
		login:  login,
	}
}

func (h *AuthHandler) Login(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
		DeviceType string `json:"device_type"`
	}

	if err := json.NewDecoder(
		r.Body,
	).
		Decode(&req); err != nil {
		h.logger.Error(ctx, "[Login] Invalid Params", err, nil)

		response.WriteError(
			w,
			errs.ErrInvalidRequest,
		)

		return
	}

	result, err :=
		h.login.Handle(
			ctx,
			login.Command{
				Email:      req.Email,
				Password:   req.Password,
				DeviceID:   req.DeviceID,
				DeviceName: req.DeviceName,
				DeviceType: session.DeviceType(req.DeviceType),
				IPAddress:  r.RemoteAddr,
				UserAgent:  r.UserAgent(),
			},
		)

	if err != nil {
		h.logger.Error(ctx, "[Login] Got error from service", err, nil)
		response.WriteError(w, err)
		return
	}

	response.WriteJSON(
		w,
		http.StatusOK,
		result,
	)
}

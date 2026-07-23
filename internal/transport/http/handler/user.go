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
		h.logger.Error(ctx, "[Register] Invalid Params", err, nil)
		response.WriteError(w, errs.ErrInvalidRequest)
		return
	}

	res, err := h.register.Handle(
		r.Context(),
		register.Command{
			Email:    req.Email,
			Password: req.Password,
		},
	)

	if err != nil {
		h.logger.Error(ctx, "[Register] Got error from service", err, nil)
		response.WriteError(w, err)
		return
	}

	response.WriteJSON(
		w,
		http.StatusCreated,
		res,
	)
}

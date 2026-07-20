package handler

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/server/http/response"
)

type AuthHandler struct {
	register *register.RegisterService
}

func NewAuthHandler(
	register *register.RegisterService,
) *AuthHandler {
	return &AuthHandler{
		register: register,
	}
}

func (h *AuthHandler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		response.WriteError(w, err)
		return
	}

	response.WriteJSON(
		w,
		http.StatusCreated,
		res,
	)
}

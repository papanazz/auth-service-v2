package health

import (
	"encoding/json"
	"net/http"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Health(
	w http.ResponseWriter,
	r *http.Request,
) {

	w.Header().
		Set(
			"Content-Type",
			"application/json",
		)

	_ = json.NewEncoder(w).
		Encode(
			map[string]string{
				"status": "ok",
			},
		)

}

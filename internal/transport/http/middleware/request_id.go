package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func RequestID(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {

			id :=
				uuid.NewString()

			ctx :=
				context.WithValue(
					r.Context(),
					requestIDKey,
					id,
				)

			w.Header().
				Set(
					"X-Request-ID",
					id,
				)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)

		},
	)
}

func GetRequestID(
	ctx context.Context,
) string {

	value, ok :=
		ctx.Value(requestIDKey).(string)

	if !ok {
		return ""
	}

	return value
}

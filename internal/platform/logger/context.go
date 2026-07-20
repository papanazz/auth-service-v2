package logger

import (
	"context"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

type contextKey string

const (
	LogIDKey     contextKey = "log_id"
	RequestIDKey contextKey = "request_id"
	TraceIDKey   contextKey = "trace_id"
)

func WithLogID(
	ctx context.Context,
	logID string,
) context.Context {

	return context.WithValue(
		ctx,
		LogIDKey,
		logID,
	)
}

func GetLogID(ctx context.Context) string {
	if ctx != nil {
		if value := ctx.Value(LogIDKey); value != nil {
			if logID, ok := value.(string); ok && logID != "" {
				return logID
			}
		}
	}

	return uuid.NewString()
}

func GetTraceID(ctx context.Context) string {
	if ctx != nil {
		span := trace.SpanFromContext(ctx)
		if span.SpanContext().SpanID().IsValid() {
			return span.SpanContext().TraceID().String()
		}
	}

	return uuid.NewString()
}

func GetRequestID(ctx context.Context) string {
	if ctx != nil {
		if value := ctx.Value(RequestIDKey); value != nil {
			if requestID, ok := value.(string); ok && requestID != "" {
				return requestID
			}
		}
	}

	return uuid.NewString()
}

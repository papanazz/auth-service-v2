package logger

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	logger *zap.Logger
}

func New(env string) (*Logger, error) {
	var (
		logger *zap.Logger
		err    error
	)

	if env == "local" {
		logger, err = zap.NewDevelopment(
			zap.AddCallerSkip(1),
			zap.AddStacktrace(zapcore.FatalLevel+1),
		)
	} else {
		logger, err = zap.NewProduction(
			zap.AddCallerSkip(1),
			zap.AddStacktrace(zapcore.FatalLevel+1),
		)
	}

	return &Logger{
		logger: logger,
	}, err
}

func (l *Logger) Info(
	ctx context.Context,
	message string,
	metadata Metadata,
) {

	l.logger.Info(
		message,
		l.metadataToArgs(
			ctx,
			metadata,
		)...,
	)
}

func (l *Logger) Debug(
	ctx context.Context,
	message string,
	metadata Metadata,
) {

	l.logger.Debug(
		message,
		l.metadataToArgs(
			ctx,
			metadata,
		)...,
	)
}

func (l *Logger) Warn(
	ctx context.Context,
	message string,
	metadata Metadata,
) {

	l.logger.Warn(
		message,
		l.metadataToArgs(
			ctx,
			metadata,
		)...,
	)
}

func (l *Logger) Error(
	ctx context.Context,
	message string,
	err error,
	metadata Metadata,
) {

	if metadata == nil {
		metadata = Metadata{}
	}

	if err != nil {
		metadata["error"] = err.Error()
	}

	l.logger.Error(
		message,
		l.metadataToArgs(
			ctx,
			metadata,
		)...,
	)
}

func (l *Logger) Fatal(
	ctx context.Context,
	message string,
	err error,
	metadata Metadata,
) {

	if metadata == nil {
		metadata = Metadata{}
	}

	if err != nil {
		metadata["error"] = err.Error()
	}

	l.logger.Fatal(
		message,
		l.metadataToArgs(
			ctx,
			metadata,
		)...,
	)
}

func (l *Logger) metadataToArgs(
	ctx context.Context,
	metadata Metadata,
) []zap.Field {

	if metadata == nil {
		metadata = Metadata{}
	}

	metadata[string(LogIDKey)] = GetLogID(ctx)
	metadata[string(TraceIDKey)] = GetTraceID(ctx)
	metadata[string(RequestIDKey)] = GetRequestID(ctx)

	args := make(
		[]zap.Field,
		0,
		len(metadata),
	)

	for key, value := range metadata {
		args = append(
			args,
			zap.Any(
				key,
				value,
			),
		)
	}

	return args
}

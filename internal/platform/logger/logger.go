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

	cfg :=
		zap.NewProductionConfig()

	if env == "local" {

		cfg.Encoding = "json"

		cfg.EncoderConfig.EncodeTime =
			zapcore.ISO8601TimeEncoder

		cfg.EncoderConfig.EncodeLevel =
			zapcore.CapitalLevelEncoder

		cfg.EncoderConfig.EncodeCaller =
			zapcore.ShortCallerEncoder
	}

	logger, err :=
		cfg.Build(
			zap.AddCallerSkip(1),
			zap.AddStacktrace(
				zapcore.FatalLevel+1,
			),
		)

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

	fields :=
		l.metadataToArgs(
			ctx,
			metadata,
		)

	if err != nil {

		fields =
			append(
				fields,
				zap.Error(err),
			)
	}

	l.logger.Error(
		message,
		fields...,
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

	fields :=
		l.metadataToArgs(
			ctx,
			metadata,
		)

	if err != nil {

		fields =
			append(
				fields,
				zap.Error(err),
			)
	}

	l.logger.Fatal(
		message,
		fields...,
	)
}

func (l *Logger) metadataToArgs(
	ctx context.Context,
	metadata Metadata,
) []zap.Field {

	fields := make(
		[]zap.Field,
		0,
		len(metadata)+3,
	)

	for key, value := range metadata {

		fields =
			append(
				fields,
				zap.Any(
					key,
					value,
				),
			)
	}

	fields =
		append(
			fields,
			zap.String(
				string(LogIDKey),
				GetLogID(ctx),
			),
			zap.String(
				string(TraceIDKey),
				GetTraceID(ctx),
			),
			zap.String(
				string(RequestIDKey),
				GetRequestID(ctx),
			),
		)

	return fields
}

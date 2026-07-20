package tracing

import (
	"context"

	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

func Init(ctx context.Context, cfg *config.Config) (func(context.Context) error, error) {
	exporter, err := otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithEndpoint(
			cfg.Observability.OTLPExporterEndpoint,
		),
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithDialOption(),
	)
	if err != nil {
		return nil, err
	}

	res, err :=
		resource.New(
			ctx,
			resource.WithAttributes(
				semconv.ServiceName(
					cfg.AppName,
				),
			),
		)

	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(
			sdktrace.AlwaysSample(),
		),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

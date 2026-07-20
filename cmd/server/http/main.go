package main

import (
	"context"
	"errors"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/papanazz/auth-service-v2/internal/app"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/tracing"
	"github.com/papanazz/auth-service-v2/internal/server/http"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		panic(err)
	}

	shutdownTracer, err := tracing.Init(ctx, cfg)
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = shutdownTracer(ctx)
	}()

	application, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Fatal(ctx, "failed to create application", err, nil)
	}

	server := http.NewServer(application)

	// Starting Server with Gracefull Handler
	go func() {
		err := server.Start()
		if err != nil &&
			!errors.Is(
				err,
				nethttp.ErrServerClosed,
			) {

			log.Fatal(
				ctx,
				"server crashed",
				err,
				nil,
			)
		}
	}()

	stop := make(chan os.Signal, 1)

	signal.Notify(

		stop,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-stop

	ctx, cancel := context.WithTimeout(
		ctx,
		10*time.Second,
	)

	defer cancel()

	_ = server.Shutdown(ctx)
}

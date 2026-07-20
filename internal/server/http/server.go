package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/papanazz/auth-service-v2/internal/app"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

type Server struct {
	logger *logger.Logger
	server *http.Server
}

func NewServer(a *app.Application) *Server {
	return &Server{
		logger: a.Logger,
		server: &http.Server{
			Addr:         fmt.Sprintf(":%d", a.Config.HTTP.Port),
			Handler:      NewRouter(a),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

}

func (s *Server) Start() error {
	s.logger.Info(
		context.TODO(),
		"server starting",
		nil,
	)

	err :=
		s.server.ListenAndServe()

	if errors.Is(
		err,
		http.ErrServerClosed,
	) {

		return nil

	}

	return err

}

func (s *Server) Shutdown(
	ctx context.Context,
) error {
	s.logger.Info(
		ctx,
		"server stopping",
		nil,
	)
	return s.server.Shutdown(ctx)

}

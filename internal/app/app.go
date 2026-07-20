package app

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
	"github.com/papanazz/auth-service-v2/internal/platform/password"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/repository"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres"
)

type Application struct {
	Config  *config.Config
	Logger  *logger.Logger
	Metrics *metrics.Metrics
	DB      *pgxpool.Pool

	RegisterService *register.RegisterService
}

func New(
	ctx context.Context,
	cfg *config.Config,
	log *logger.Logger,
) (*Application, error) {

	db, err := postgres.New(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	queries := sqlc.New(db)

	passwordRepository := password.NewBcrypt()

	userRepository := repository.NewUserRepository(queries)

	registerService := register.NewService(userRepository, passwordRepository)

	return &Application{
		Config:  cfg,
		Logger:  log,
		DB:      db,
		Metrics: metrics.New(),

		RegisterService: registerService,
	}, nil

}

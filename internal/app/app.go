package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
	"github.com/papanazz/auth-service-v2/internal/platform/password"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/repository"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
	"github.com/papanazz/auth-service-v2/internal/platform/token"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres"
)

type Application struct {
	Config  *config.Config
	Logger  *logger.Logger
	Metrics *metrics.Metrics
	DB      *pgxpool.Pool

	RegisterService *register.RegisterService
	LoginService    *login.LoginService
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

	passwordRepository := password.NewArgon2id()
	jwtService := token.NewJWTService(
		cfg.Token.SecretKey,
		time.Duration(cfg.Token.TokenTTLInSeconds)*time.Second,
	)

	refreshGenerator := token.NewRandomGenerator()
	hasher := token.NewSHA256Hasher()

	userRepository := repository.NewUserRepository(queries)
	sessionRepository := repository.NewSessionRepository(queries)
	refreshTokenRepository := repository.NewRefreshTokenRepository(cfg.Token.TokenRefreshInSeconds, queries)

	registerService := register.NewService(userRepository, passwordRepository)
	loginService := login.NewService(userRepository, passwordRepository, sessionRepository, refreshTokenRepository, jwtService, refreshGenerator, hasher)

	return &Application{
		Config:  cfg,
		Logger:  log,
		DB:      db,
		Metrics: metrics.New(),

		RegisterService: registerService,
		LoginService:    loginService,
	}, nil

}

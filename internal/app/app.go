package app

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
	"github.com/papanazz/auth-service-v2/internal/platform/password"
	postgresRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
	"github.com/papanazz/auth-service-v2/internal/platform/redis"
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

	transactionManager := postgresRepo.NewTransactionManager(db)
	queries := sqlc.New(db)

	redis, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return nil, err
	}

	passwordRepository := password.NewArgon2id()
	jwtService := token.NewJWTService(
		cfg.Security.JWT.SecretKey,
		cfg.Security.JWT.TTL,
	)

	refreshGenerator := token.NewRandomGenerator()
	hasher := token.NewSHA256Hasher()

	loginPolicy :=
		login.SecurityPolicy{

			IP: security.LimitPolicy{

				Limit: cfg.Security.Login.IP.Limit,

				Window: cfg.Security.Login.IP.Window,
			},

			Credential: security.LimitPolicy{

				Limit: cfg.Security.Login.Email.Limit,

				Window: cfg.Security.Login.Email.Window,
			},
		}

	attemptTracker :=
		authattempt.NewRedisTracker(
			redis.Client,
		)

	userRepository := postgresRepo.NewUserRepository(queries)
	sessionRepository := postgresRepo.NewSessionRepository(queries)
	refreshTokenRepository := postgresRepo.NewRefreshTokenRepository(cfg.Security.RefreshToken.TTL, queries)
	auditRepository := postgresRepo.NewAuditRepository(queries)

	registerService := register.NewService(userRepository, passwordRepository)
	loginService := login.NewService(
		transactionManager,
		userRepository,
		sessionRepository,
		refreshTokenRepository,
		passwordRepository,
		auditRepository,
		jwtService,
		refreshGenerator,
		hasher,
		attemptTracker,
		loginPolicy,
	)

	return &Application{
		Config:  cfg,
		Logger:  log,
		DB:      db,
		Metrics: metrics.New(),

		RegisterService: registerService,
		LoginService:    loginService,
	}, nil

}

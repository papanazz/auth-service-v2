package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/app/auth/logout"
	"github.com/papanazz/auth-service-v2/internal/app/auth/refresh"
	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/app/user/resendverification"
	"github.com/papanazz/auth-service-v2/internal/app/user/verifyemail"

	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/email"
	"github.com/papanazz/auth-service-v2/internal/platform/idempotency"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
	"github.com/papanazz/auth-service-v2/internal/platform/token"

	"github.com/papanazz/auth-service-v2/internal/platform/password"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
	"github.com/papanazz/auth-service-v2/internal/platform/refresh_token"
	verificationPlatform "github.com/papanazz/auth-service-v2/internal/platform/verification"

	"github.com/papanazz/auth-service-v2/internal/platform/redis"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres"
	postgresRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository"
	auditRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/audit"
	refreshRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/refresh_token"
	sessionRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/session"
	userRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/user"
	verificationRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/verification"
)

type Application struct {
	Config *config.Config

	Logger *logger.Logger

	Metrics *metrics.Metrics

	DB *pgxpool.Pool

	RegisterService *register.RegisterService

	LoginService *login.LoginService

	RefreshService *refresh.Service

	LogoutService *logout.Service

	VerifyEmailService *verifyemail.Service

	ResendVerificationService *resendverification.Service

	IdempotencyStore *idempotency.Store
}

func New(
	ctx context.Context,
	cfg *config.Config,
	log *logger.Logger,
) (*Application, error) {

	db, err :=
		postgres.New(
			ctx,
			cfg.Database,
		)

	if err != nil {
		return nil, err
	}

	queries :=
		sqlc.New(
			db,
		)

	transactionManager :=
		postgresRepo.NewTransactionManager(
			db,
			5*time.Second,
		)

	redisClient, err :=
		redis.New(
			ctx,
			cfg.Redis,
		)

	if err != nil {
		return nil, err
	}

	// =========================
	// Security providers
	// =========================

	passwordHasher :=
		password.NewArgon2id()

	jwtService :=
		token.NewJWTService(

			cfg.Security.JWT.SecretKey,

			cfg.Security.JWT.TTL,
		)

	refreshGenerator :=
		refresh_token.NewRandomGenerator()

	refreshHasher :=
		refresh_token.NewSHA256Hasher()

	verificationGenerator :=
		verificationPlatform.NewRandomGenerator()

	verificationHasher :=
		verificationPlatform.NewSHA256Hasher()

	verificationCache :=
		verificationPlatform.NewRedisCache(
			redisClient.Client,
		)

	emailPublisher :=
		email.NewLogPublisher(
			log,
		)

		// =========================
		// Repositories
		// =========================

	userRepository :=
		userRepo.NewUserRepository(
			queries,
		)

	sessionRepository :=
		sessionRepo.NewSessionRepository(
			queries,
		)

	refreshTokenRepository :=
		refreshRepo.NewRefreshTokenRepository(
			queries,
		)

	verificationTokenRepository :=
		verificationRepo.NewVerificationRepository(
			queries,
		)

	auditPublisher :=
		auditRepo.NewAuditPublisher(
			queries,
		)

		// =========================
		// Security policies
		// =========================

	loginPolicy :=
		newLoginSecurityPolicy(cfg)

	registerPolicy :=
		newRegisterSecurityPolicy(cfg)

	resendVerificationPolicy :=
		newResendVerificationSecurityPolicy(cfg)

	attemptTracker :=
		authattempt.NewRedisTracker(
			redisClient.Client,
		)

	idempotencyStore :=
		idempotency.NewStore(
			redisClient.Client,
		)

	// =========================
	// Application services
	// =========================

	registerService :=
		register.NewService(
			transactionManager,
			userRepository,
			verificationTokenRepository,
			verificationCache,
			verificationGenerator,
			verificationHasher,
			emailPublisher,
			passwordHasher,
			password.NewPolicy(),
			auditPublisher,
			attemptTracker,
			registerPolicy,
		)

	loginService :=
		login.NewService(
			transactionManager,
			userRepository,
			sessionRepository,
			refreshTokenRepository,
			passwordHasher,
			jwtService,
			refreshGenerator,
			refreshHasher,
			auditPublisher,
			attemptTracker,
			loginPolicy,
		)

	refreshService :=
		refresh.NewService(

			transactionManager,

			refreshTokenRepository,

			sessionRepository,

			jwtService,

			refreshGenerator,

			refreshHasher,

			auditPublisher,

			cfg.Security.RefreshToken.TTL,
		)

	logoutService :=
		logout.NewService(

			transactionManager,

			refreshTokenRepository,

			sessionRepository,

			refreshHasher,

			auditPublisher,
		)

	verifyEmailService :=
		verifyemail.NewService(
			transactionManager,
			verificationTokenRepository,
			userRepository,
			verificationHasher,
			auditPublisher,
		)

	resendVerificationService :=
		resendverification.NewService(
			userRepository,
			verificationTokenRepository,
			verificationCache,
			verificationGenerator,
			verificationHasher,
			emailPublisher,
			auditPublisher,
			attemptTracker,
			resendVerificationPolicy,
		)

	return &Application{

		Config: cfg,

		Logger: log,

		DB: db,

		Metrics: metrics.New(),

		RegisterService: registerService,

		LoginService: loginService,

		RefreshService: refreshService,

		LogoutService: logoutService,

		VerifyEmailService: verifyEmailService,

		ResendVerificationService: resendVerificationService,

		IdempotencyStore: idempotencyStore,
	}, nil

}

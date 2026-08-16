package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/app/auth/logout"
	"github.com/papanazz/auth-service-v2/internal/app/auth/oauthcallback"
	"github.com/papanazz/auth-service-v2/internal/app/auth/oauthstart"
	"github.com/papanazz/auth-service-v2/internal/app/auth/refresh"
	"github.com/papanazz/auth-service-v2/internal/app/auth/sessionissuer"
	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/app/user/resendverification"
	"github.com/papanazz/auth-service-v2/internal/app/user/verifyemail"

	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
	"github.com/papanazz/auth-service-v2/internal/platform/email"
	"github.com/papanazz/auth-service-v2/internal/platform/idempotency"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
	oauthPlatform "github.com/papanazz/auth-service-v2/internal/platform/oauth"
	"github.com/papanazz/auth-service-v2/internal/platform/oauth/google"
	"github.com/papanazz/auth-service-v2/internal/platform/oauthstate"
	"github.com/papanazz/auth-service-v2/internal/platform/token"
	"github.com/papanazz/auth-service-v2/internal/platform/tracing"

	"github.com/papanazz/auth-service-v2/internal/platform/password"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
	"github.com/papanazz/auth-service-v2/internal/platform/refresh_token"
	verificationPlatform "github.com/papanazz/auth-service-v2/internal/platform/verification"

	"github.com/papanazz/auth-service-v2/internal/platform/redis"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres"
	postgresRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository"
	auditRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/audit"
	oauthIdentityRepo "github.com/papanazz/auth-service-v2/internal/platform/postgres/repository/oauthidentity"
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

	Redis *redis.Cache

	RegisterService *register.RegisterService

	LoginService *login.LoginService

	RefreshService *refresh.Service

	LogoutService *logout.Service

	VerifyEmailService *verifyemail.Service

	ResendVerificationService *resendverification.Service

	OAuthStartService *oauthstart.Service

	OAuthCallbackService *oauthcallback.Service

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

	appMetrics :=
		metrics.New()

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

	googleExchanger :=
		google.NewExchanger(
			cfg.OAuth.Google.ClientID,
			cfg.OAuth.Google.ClientSecret,
			cfg.OAuth.Google.RedirectURL,
		)

	oauthStateStore :=
		oauthstate.NewStore(
			redisClient.Client,
		)

	oauthGenerator :=
		oauthPlatform.NewRandomGenerator()

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

	oauthIdentityRepository :=
		oauthIdentityRepo.NewRepository(
			queries,
		)

	auditPublisher :=
		metrics.NewAuditPublisher(
			tracing.NewAuditPublisher(
				auditRepo.NewAuditPublisher(
					queries,
				),
			),
			appMetrics,
		)

		// =========================
		// Security policies
		// =========================

	loginPolicy :=
		newLoginSecurityPolicy(cfg)

	sessionIssuerPolicy :=
		newSessionIssuerPolicy(cfg)

	registerPolicy :=
		newRegisterSecurityPolicy(cfg)

	resendVerificationPolicy :=
		newResendVerificationSecurityPolicy(cfg)

	oauthStartPolicy :=
		newOAuthStartPolicy(cfg)

	oauthCallbackPolicy :=
		newOAuthCallbackPolicy(cfg)

	attemptTracker :=
		authattempt.NewRedisTracker(
			redisClient.Client,
			appMetrics,
		)

	idempotencyStore :=
		idempotency.NewStore(
			redisClient.Client,
		)

	// sessionIssuer mints a session + refresh token + access token for
	// one account on one device — shared by login and OAuth login alike
	// (docs/oauth.md), rather than each having its own copy of the
	// device-slot/transaction logic.
	sessionIssuer :=
		sessionissuer.NewIssuer(
			transactionManager,
			sessionRepository,
			refreshTokenRepository,
			jwtService,
			refreshGenerator,
			refreshHasher,
			sessionIssuerPolicy,
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
			log,
			registerPolicy,
		)

	loginService :=
		login.NewService(
			userRepository,
			passwordHasher,
			sessionIssuer,
			auditPublisher,
			attemptTracker,
			log,
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

			log,

			cfg.Security.RefreshToken.TTL,
		)

	logoutService :=
		logout.NewService(

			transactionManager,

			refreshTokenRepository,

			sessionRepository,

			refreshHasher,

			auditPublisher,

			log,
		)

	verifyEmailService :=
		verifyemail.NewService(
			transactionManager,
			verificationTokenRepository,
			userRepository,
			verificationHasher,
			auditPublisher,
			log,
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
			log,
			resendVerificationPolicy,
		)

	oauthStartService :=
		oauthstart.NewService(
			googleExchanger,
			oauthStateStore,
			oauthGenerator,
			oauthStartPolicy,
		)

	oauthCallbackService :=
		oauthcallback.NewService(
			googleExchanger,
			oauthStateStore,
			oauthIdentityRepository,
			userRepository,
			sessionIssuer,
			transactionManager,
			verificationTokenRepository,
			verificationCache,
			verificationGenerator,
			verificationHasher,
			emailPublisher,
			auditPublisher,
			log,
			oauthCallbackPolicy,
		)

	return &Application{

		Config: cfg,

		Logger: log,

		DB: db,

		Redis: redisClient,

		Metrics: appMetrics,

		RegisterService: registerService,

		LoginService: loginService,

		RefreshService: refreshService,

		LogoutService: logoutService,

		VerifyEmailService: verifyEmailService,

		ResendVerificationService: resendVerificationService,

		OAuthStartService: oauthStartService,

		OAuthCallbackService: oauthCallbackService,

		IdempotencyStore: idempotencyStore,
	}, nil

}

package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	App               AppConfig
	Server            ServerConfig
	Database          DatabaseConfig
	Redis             RedisConfig
	Security          SecurityConfig
	Idempotency       IdempotencyConfig
	EmailVerification EmailVerificationConfig
	Observability     ObservabilityConfig
}

type AppConfig struct {
	Name     string `env:"APP_NAME" envDefault:"auth-service"`
	Env      string `env:"APP_ENV" envDefault:"development"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"debug"`
}

type ServerConfig struct {
	HTTP HTTPConfig
	GRPC GRPCConfig
}

type HTTPConfig struct {
	Port            int           `env:"HTTP_PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

type GRPCConfig struct {
	Port int `env:"GRPC_PORT" envDefault:"9090"`
}

type DatabaseConfig struct {
	URL string `env:"DATABASE_URL"`

	MaxConnections        int32         `env:"DATABASE_MAX_CONNECTIONS" envDefault:"20"`
	MinConnections        int32         `env:"DATABASE_MIN_CONNECTIONS" envDefault:"5"`
	MaxConnectionLifetime time.Duration `env:"DATABASE_MAX_CONNECTION_LIFETIME" envDefault:"30m"`
	MaxConnectionIdleTime time.Duration `env:"DATABASE_MAX_CONNECTION_IDLE_TIME" envDefault:"5m"`
	HealthCheckPeriod     time.Duration `env:"DATABASE_HEALTH_CHECK_PERIOD" envDefault:"1m"`
}

type RedisConfig struct {
	Address  string `env:"REDIS_ADDRESS" envDefault:"localhost:6379"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB" envDefault:"0"`

	PoolSize           int           `env:"REDIS_POOL_SIZE" envDefault:"20"`
	MinIdleConnections int           `env:"REDIS_MIN_IDLE_CONNECTIONS" envDefault:"5"`
	DialTimeout        time.Duration `env:"REDIS_DIAL_TIMEOUT" envDefault:"5s"`
	ReadTimeout        time.Duration `env:"REDIS_READ_TIMEOUT" envDefault:"3s"`
	WriteTimeout       time.Duration `env:"REDIS_WRITE_TIMEOUT" envDefault:"3s"`
	PoolTimeout        time.Duration `env:"REDIS_POOL_TIMEOUT" envDefault:"4s"`
	IdleTimeout        time.Duration `env:"REDIS_IDLE_TIMEOUT" envDefault:"5m"`
}

type SecurityConfig struct {
	JWT          JWTConfig
	RefreshToken RefreshTokenConfig
	Session      SessionConfig
	Login        LoginSecurityConfig
	Register     RegisterSecurityConfig
}

type JWTConfig struct {
	SecretKey string        `env:"JWT_SECRET_KEY"`
	TTL       time.Duration `env:"JWT_TTL" envDefault:"15m"`
}

type RefreshTokenConfig struct {
	TTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"720h"`
}

// SessionConfig bounds how long an authenticated session may live.
//
// It must be at least as long as RefreshTokenConfig.TTL: a refresh token is
// only usable while its owning session is still active, so a shorter session
// TTL would silently invalidate tokens that have not yet expired.
type SessionConfig struct {
	TTL time.Duration `env:"SESSION_TTL" envDefault:"2160h"`
}

type LoginSecurityConfig struct {
	IP     LoginIPConfig
	Email  LoginEmailConfig
	Device LoginDeviceConfig
}

type LoginIPConfig struct {
	Limit  int           `env:"LOGIN_IP_LIMIT" envDefault:"20"`
	Window time.Duration `env:"LOGIN_IP_WINDOW" envDefault:"1m"`
}

type LoginEmailConfig struct {
	Limit  int           `env:"LOGIN_EMAIL_LIMIT" envDefault:"5"`
	Window time.Duration `env:"LOGIN_EMAIL_WINDOW" envDefault:"15m"`
}

// LoginDeviceConfig bounds how a login is treated when the same device
// already holds an active session.
//
// Within GracePeriod of that session's creation, a new login is assumed to
// be the same client retrying (e.g. after a network timeout) rather than a
// second, competing login: the stale session is superseded and the new
// login proceeds. Past the grace period, the new login is rejected instead
// of silently killing a session that has been active for a while — that is
// more likely a bug or an attacker than a retry.
type LoginDeviceConfig struct {
	GracePeriod time.Duration `env:"LOGIN_DEVICE_GRACE_PERIOD" envDefault:"5m"`
}

type RegisterSecurityConfig struct {
	IP RegisterIPConfig
}

// RegisterIPConfig caps how many registrations a single IP may attempt in
// the window, regardless of outcome — a validation failure or a duplicate
// email still counts, since both are exactly what an account-creation or
// email-enumeration bot generates in bulk. Tighter than login's IP limit:
// registration is a rarer legitimate action per IP than login is.
type RegisterIPConfig struct {
	Limit  int           `env:"REGISTER_IP_LIMIT" envDefault:"5"`
	Window time.Duration `env:"REGISTER_IP_WINDOW" envDefault:"10m"`
}

// IdempotencyConfig bounds how long a cached response stays replayable for
// a given Idempotency-Key. Long enough to cover a client's retry window
// after a dropped connection, short enough that the header can't be reused
// to relive an old request indefinitely.
type IdempotencyConfig struct {
	TTL time.Duration `env:"IDEMPOTENCY_KEY_TTL" envDefault:"10m"`
}

type EmailVerificationConfig struct {
	// TokenTTL bounds how long an issued verification token stays valid.
	// Also the TTL of its short-lived raw-value cache in Redis (see
	// domain/verification.Cache) — the two are the same window by
	// construction.
	TokenTTL time.Duration `env:"EMAIL_VERIFICATION_TOKEN_TTL" envDefault:"24h"`

	Resend ResendVerificationConfig
}

// ResendVerificationConfig caps how many resend requests a single IP may
// attempt in the window, regardless of whether the email exists or is
// already verified — the response is identical in every case (see
// docs/email-verification.md), so the rate limit is the only thing
// standing between this endpoint and being used to spam an arbitrary
// inbox with verification emails.
type ResendVerificationConfig struct {
	Limit  int           `env:"RESEND_VERIFICATION_IP_LIMIT" envDefault:"3"`
	Window time.Duration `env:"RESEND_VERIFICATION_IP_WINDOW" envDefault:"10m"`
}

type ObservabilityConfig struct {
	OTLPExporterEndpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:"localhost:4317"`
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env")

	if appEnv := os.Getenv("APP_ENV"); appEnv != "" {
		_ = godotenv.Overload(".env." + appEnv)
	}

	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Database.URL == "" {
		return errors.New("DATABASE_URL is required")
	}

	if c.Security.JWT.SecretKey == "" {
		return errors.New("JWT_SECRET_KEY is required")
	}

	if c.Security.JWT.TTL <= 0 {
		return errors.New("JWT_TTL must be positive")
	}

	if c.Security.RefreshToken.TTL <= 0 {
		return errors.New("REFRESH_TOKEN_TTL must be positive")
	}

	if c.Security.Session.TTL <= 0 {
		return errors.New("SESSION_TTL must be positive")
	}

	if c.Security.Login.Device.GracePeriod < 0 {
		return errors.New("LOGIN_DEVICE_GRACE_PERIOD must not be negative")
	}

	if c.Idempotency.TTL <= 0 {
		return errors.New("IDEMPOTENCY_KEY_TTL must be positive")
	}

	if c.EmailVerification.TokenTTL <= 0 {
		return errors.New("EMAIL_VERIFICATION_TOKEN_TTL must be positive")
	}

	// A refresh token is only honoured while its session is still active, so a
	// session that expires first silently rejects tokens that have not expired
	// yet. Fail at startup instead of at 3am.
	if c.Security.Session.TTL < c.Security.RefreshToken.TTL {
		return fmt.Errorf(
			"SESSION_TTL (%s) must be greater than or equal to REFRESH_TOKEN_TTL (%s), "+
				"otherwise refresh tokens are rejected by an expired session before they expire",
			c.Security.Session.TTL,
			c.Security.RefreshToken.TTL,
		)
	}

	// An access token that outlives its refresh token cannot be rotated away,
	// which defeats the point of short-lived access tokens.
	if c.Security.JWT.TTL > c.Security.RefreshToken.TTL {
		return fmt.Errorf(
			"JWT_TTL (%s) must not exceed REFRESH_TOKEN_TTL (%s)",
			c.Security.JWT.TTL,
			c.Security.RefreshToken.TTL,
		)
	}

	return nil
}

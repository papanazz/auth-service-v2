package config

import (
	"strings"
	"testing"
	"time"
)

// validConfig returns the minimum configuration that Validate accepts, so each
// test can break exactly one thing.
func validConfig() *Config {

	cfg := &Config{}

	cfg.Database.URL = "postgres://localhost:5432/auth?sslmode=disable"

	cfg.Security.JWT.SecretKey = "secret"
	cfg.Security.JWT.TTL = 15 * time.Minute

	cfg.Security.RefreshToken.TTL = 720 * time.Hour
	cfg.Security.Session.TTL = 2160 * time.Hour

	cfg.Idempotency.TTL = 10 * time.Minute

	cfg.EmailVerification.TokenTTL = 24 * time.Hour

	return cfg
}

func TestConfig_Validate(t *testing.T) {

	tests := []struct {
		name string

		mutate func(c *Config)

		// substring expected in the error; empty means the config must pass
		wantErr string
	}{
		{
			name: "accepts a complete configuration",

			mutate: func(c *Config) {},
		},
		{
			name: "requires a database URL",

			mutate: func(c *Config) {
				c.Database.URL = ""
			},

			wantErr: "DATABASE_URL",
		},
		{
			name: "requires a JWT secret",

			mutate: func(c *Config) {
				c.Security.JWT.SecretKey = ""
			},

			wantErr: "JWT_SECRET_KEY",
		},
		{
			name: "rejects a non-positive JWT TTL",

			mutate: func(c *Config) {
				c.Security.JWT.TTL = 0
			},

			wantErr: "JWT_TTL must be positive",
		},
		{
			name: "rejects a non-positive refresh token TTL",

			mutate: func(c *Config) {
				c.Security.RefreshToken.TTL = 0
			},

			wantErr: "REFRESH_TOKEN_TTL must be positive",
		},
		{
			name: "rejects a non-positive session TTL",

			mutate: func(c *Config) {
				c.Security.Session.TTL = 0
			},

			wantErr: "SESSION_TTL must be positive",
		},
		{
			name: "rejects a session shorter than the refresh token",

			mutate: func(c *Config) {
				c.Security.RefreshToken.TTL = 720 * time.Hour
				c.Security.Session.TTL = 24 * time.Hour
			},

			wantErr: "SESSION_TTL",
		},
		{
			name: "accepts a session exactly as long as the refresh token",

			mutate: func(c *Config) {
				c.Security.RefreshToken.TTL = 720 * time.Hour
				c.Security.Session.TTL = 720 * time.Hour
			},
		},
		{
			name: "rejects an access token outliving the refresh token",

			mutate: func(c *Config) {
				c.Security.JWT.TTL = 800 * time.Hour
			},

			wantErr: "JWT_TTL",
		},
		{
			name: "rejects a negative device login grace period",

			mutate: func(c *Config) {
				c.Security.Login.Device.GracePeriod = -time.Second
			},

			wantErr: "LOGIN_DEVICE_GRACE_PERIOD",
		},
		{
			name: "accepts a zero device login grace period",

			mutate: func(c *Config) {
				c.Security.Login.Device.GracePeriod = 0
			},
		},
		{
			name: "rejects a non-positive idempotency key TTL",

			mutate: func(c *Config) {
				c.Idempotency.TTL = 0
			},

			wantErr: "IDEMPOTENCY_KEY_TTL must be positive",
		},
		{
			name: "rejects a non-positive email verification token TTL",

			mutate: func(c *Config) {
				c.EmailVerification.TokenTTL = 0
			},

			wantErr: "EMAIL_VERIFICATION_TOKEN_TTL must be positive",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			cfg := validConfig()

			tt.mutate(cfg)

			err := cfg.Validate()

			if tt.wantErr == "" {

				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// The defaults declared on the struct tags must themselves satisfy Validate,
// otherwise the service cannot start without extra configuration.
func TestLoad_ShippedDefaultsAreValid(t *testing.T) {

	t.Setenv("DATABASE_URL", "postgres://localhost:5432/auth?sslmode=disable")
	t.Setenv("JWT_SECRET_KEY", "test-secret")

	cfg, err := Load()

	if err != nil {
		t.Fatalf("default configuration is invalid: %v", err)
	}

	if cfg.Security.Session.TTL < cfg.Security.RefreshToken.TTL {
		t.Errorf(
			"default SESSION_TTL %v is shorter than default REFRESH_TOKEN_TTL %v",
			cfg.Security.Session.TTL,
			cfg.Security.RefreshToken.TTL,
		)
	}
}

package app

import (
	"reflect"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/platform/config"
)

func testConfig() *config.Config {

	cfg := &config.Config{}

	cfg.Security.Login.IP.Limit = 20
	cfg.Security.Login.IP.Window = time.Minute

	cfg.Security.Login.Email.Limit = 5
	cfg.Security.Login.Email.Window = 15 * time.Minute

	cfg.Security.RefreshToken.TTL = 720 * time.Hour
	cfg.Security.Session.TTL = 2160 * time.Hour

	cfg.Security.Login.Device.GracePeriod = 5 * time.Minute

	cfg.Security.Register.IP.Limit = 5
	cfg.Security.Register.IP.Window = 10 * time.Minute

	cfg.EmailVerification.TokenTTL = 24 * time.Hour

	cfg.EmailVerification.Resend.Limit = 3
	cfg.EmailVerification.Resend.Window = 10 * time.Minute

	return cfg
}

// zeroFields walks a struct and reports the dotted path of every field left at
// its zero value.
//
// Using reflection rather than a hand-written list is the point: a field added
// to SecurityPolicy later is covered automatically, instead of being silently
// unwired the way RefreshTokenTTL once was.
func zeroFields(
	value reflect.Value,
	prefix string,
) []string {

	var found []string

	valueType := value.Type()

	for i := 0; i < value.NumField(); i++ {

		field := value.Field(i)

		name := prefix + valueType.Field(i).Name

		// Time durations and ints are leaves; structs recurse.
		if field.Kind() == reflect.Struct &&
			field.Type() != reflect.TypeOf(time.Time{}) {

			found = append(
				found,
				zeroFields(field, name+".")...,
			)

			continue
		}

		if field.IsZero() {
			found = append(found, name)
		}
	}

	return found
}

// Regression test for a wiring bug that no use-case test could catch: login
// tests build SecurityPolicy themselves, so RefreshTokenTTL being absent from
// app.New went unnoticed until every issued refresh token was born expired.
func TestNewLoginSecurityPolicy_WiresEveryField(t *testing.T) {

	policy := newLoginSecurityPolicy(testConfig())

	if missing := zeroFields(
		reflect.ValueOf(policy),
		"",
	); len(missing) > 0 {

		t.Errorf(
			"SecurityPolicy fields left unwired by newLoginSecurityPolicy: %v",
			missing,
		)
	}
}

func TestNewLoginSecurityPolicy_CarriesConfiguredValues(t *testing.T) {

	cfg := testConfig()

	policy := newLoginSecurityPolicy(cfg)

	tests := []struct {
		name string

		got any

		want any
	}{
		{"IP limit", policy.IP.Limit, cfg.Security.Login.IP.Limit},
		{"IP window", policy.IP.Window, cfg.Security.Login.IP.Window},
		{"credential limit", policy.Credential.Limit, cfg.Security.Login.Email.Limit},
		{"credential window", policy.Credential.Window, cfg.Security.Login.Email.Window},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestNewRegisterSecurityPolicy_WiresEveryField(t *testing.T) {

	policy := newRegisterSecurityPolicy(testConfig())

	if missing := zeroFields(
		reflect.ValueOf(policy),
		"",
	); len(missing) > 0 {

		t.Errorf(
			"SecurityPolicy fields left unwired by newRegisterSecurityPolicy: %v",
			missing,
		)
	}
}

func TestNewRegisterSecurityPolicy_CarriesConfiguredValues(t *testing.T) {

	cfg := testConfig()

	policy := newRegisterSecurityPolicy(cfg)

	if policy.IP.Limit != cfg.Security.Register.IP.Limit {
		t.Errorf("IP limit = %v, want %v", policy.IP.Limit, cfg.Security.Register.IP.Limit)
	}

	if policy.IP.Window != cfg.Security.Register.IP.Window {
		t.Errorf("IP window = %v, want %v", policy.IP.Window, cfg.Security.Register.IP.Window)
	}

	if policy.EmailVerificationTokenTTL != cfg.EmailVerification.TokenTTL {
		t.Errorf(
			"email verification token TTL = %v, want %v",
			policy.EmailVerificationTokenTTL,
			cfg.EmailVerification.TokenTTL,
		)
	}
}

func TestNewResendVerificationSecurityPolicy_WiresEveryField(t *testing.T) {

	policy := newResendVerificationSecurityPolicy(testConfig())

	if missing := zeroFields(
		reflect.ValueOf(policy),
		"",
	); len(missing) > 0 {

		t.Errorf(
			"SecurityPolicy fields left unwired by newResendVerificationSecurityPolicy: %v",
			missing,
		)
	}
}

func TestNewResendVerificationSecurityPolicy_CarriesConfiguredValues(t *testing.T) {

	cfg := testConfig()

	policy := newResendVerificationSecurityPolicy(cfg)

	if policy.IP.Limit != cfg.EmailVerification.Resend.Limit {
		t.Errorf("IP limit = %v, want %v", policy.IP.Limit, cfg.EmailVerification.Resend.Limit)
	}

	if policy.IP.Window != cfg.EmailVerification.Resend.Window {
		t.Errorf("IP window = %v, want %v", policy.IP.Window, cfg.EmailVerification.Resend.Window)
	}

	if policy.TokenTTL != cfg.EmailVerification.TokenTTL {
		t.Errorf("token TTL = %v, want %v", policy.TokenTTL, cfg.EmailVerification.TokenTTL)
	}
}

func TestNewSessionIssuerPolicy_WiresEveryField(t *testing.T) {

	policy := newSessionIssuerPolicy(testConfig())

	if missing := zeroFields(
		reflect.ValueOf(policy),
		"",
	); len(missing) > 0 {

		t.Errorf(
			"Policy fields left unwired by newSessionIssuerPolicy: %v",
			missing,
		)
	}
}

func TestNewSessionIssuerPolicy_CarriesConfiguredValues(t *testing.T) {

	cfg := testConfig()

	policy := newSessionIssuerPolicy(cfg)

	if policy.RefreshTokenTTL != cfg.Security.RefreshToken.TTL {
		t.Errorf("refresh token TTL = %v, want %v", policy.RefreshTokenTTL, cfg.Security.RefreshToken.TTL)
	}

	if policy.SessionTTL != cfg.Security.Session.TTL {
		t.Errorf("session TTL = %v, want %v", policy.SessionTTL, cfg.Security.Session.TTL)
	}

	if policy.DeviceGracePeriod != cfg.Security.Login.Device.GracePeriod {
		t.Errorf("device grace period = %v, want %v", policy.DeviceGracePeriod, cfg.Security.Login.Device.GracePeriod)
	}
}

// A refresh token is only accepted while its session is still active, so a
// session that expires first would reject tokens that have not expired yet.
func TestNewSessionIssuerPolicy_SessionOutlivesRefreshToken(t *testing.T) {

	policy := newSessionIssuerPolicy(testConfig())

	if policy.SessionTTL < policy.RefreshTokenTTL {
		t.Errorf(
			"session TTL %v is shorter than refresh token TTL %v: valid tokens would be rejected by an expired session",
			policy.SessionTTL,
			policy.RefreshTokenTTL,
		)
	}
}

// The same invariant has to hold for the values the service actually ships
// with, not just the ones this test file picks.
func TestShippedDefaults_SessionOutlivesRefreshToken(t *testing.T) {

	// Only the two keys Validate insists on; everything else falls back to the
	// envDefault declared on the config struct.
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/auth?sslmode=disable")
	t.Setenv("JWT_SECRET_KEY", "test-secret")

	cfg, err := config.Load()

	if err != nil {
		t.Fatalf("loading defaults: %v", err)
	}

	policy := newSessionIssuerPolicy(cfg)

	if policy.RefreshTokenTTL <= 0 {
		t.Error("default REFRESH_TOKEN_TTL is not positive")
	}

	if policy.SessionTTL <= 0 {
		t.Error("default SESSION_TTL is not positive")
	}

	if policy.SessionTTL < policy.RefreshTokenTTL {
		t.Errorf(
			"default SESSION_TTL %v is shorter than default REFRESH_TOKEN_TTL %v",
			policy.SessionTTL,
			policy.RefreshTokenTTL,
		)
	}
}

package authattempt

import "testing"

// limiterFromKey backs the RateLimitRejectionsTotal label — it must never
// let the identifying suffix (an IP address or a credential hash) through,
// since that would turn a handful of bounded time series into one per
// caller.
func TestLimiterFromKey(t *testing.T) {

	tests := []struct {
		name string

		key string

		want string
	}{
		{
			name: "login IP limiter",
			key:  LoginIP("203.0.113.10:54321"),
			want: "auth:login:ip",
		},
		{
			name: "login credential limiter",
			key:  LoginCredential("bayu@example.com", "203.0.113.10:54321"),
			want: "auth:login:credential",
		},
		{
			name: "register IP limiter",
			key:  RegisterIP("203.0.113.10:54321"),
			want: "auth:register:ip",
		},
		{
			name: "resend-verification IP limiter",
			key:  ResendVerificationIP("203.0.113.10:54321"),
			want: "auth:resend-verification:ip",
		},
		{
			name: "a key with fewer than 3 segments falls back to a fixed label, never itself",
			key:  "malformed",
			want: "unknown",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if got := limiterFromKey(tt.key); got != tt.want {
				t.Errorf("limiterFromKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// The identifying suffix must never leak into the label, whatever it is —
// this is the property the fixed-prefix tests above are really guarding.
func TestLimiterFromKey_NeverIncludesTheSuffix(t *testing.T) {

	key := LoginCredential("bayu@example.com", "203.0.113.10:54321")

	got := limiterFromKey(key)

	if got == key {
		t.Fatalf("limiterFromKey returned the full key unmodified: %q", got)
	}

	if len(got) >= len(key) {
		t.Errorf("limiterFromKey(%q) = %q, expected it to be shorter than the input", key, got)
	}
}

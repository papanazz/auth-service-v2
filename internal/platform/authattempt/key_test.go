package authattempt

import "testing"

// The transport layer passes http.Request.RemoteAddr straight through,
// which always carries a port. Before this was handled, every connection
// from the same client produced a distinct rate-limit key — a new
// ephemeral source port each time — so the sliding window never
// accumulated and the limiter never actually tripped.
func TestNormalizeIP(t *testing.T) {

	tests := []struct {
		name string

		input string

		want string
	}{
		{
			name:  "IPv4 with port, as RemoteAddr supplies it",
			input: "203.0.113.10:54321",
			want:  "203.0.113.10",
		},
		{
			name:  "IPv6 with port and brackets",
			input: "[2001:db8::1]:54321",
			want:  "2001:db8::1",
		},
		{
			name:  "bare IPv4",
			input: "203.0.113.10",
			want:  "203.0.113.10",
		},
		{
			name:  "empty value passes through unchanged",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if got := normalizeIP(tt.input); got != tt.want {
				t.Errorf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// The regression this actually guards against: two connections from the
// same client, different ephemeral ports, must produce the same key.
func TestLoginIP_SameClientDifferentPortsProducesTheSameKey(t *testing.T) {

	first := LoginIP("203.0.113.10:54321")

	second := LoginIP("203.0.113.10:60000")

	if first != second {
		t.Errorf("LoginIP produced different keys for the same client on different ports: %q vs %q", first, second)
	}
}

func TestRegisterIP_SameClientDifferentPortsProducesTheSameKey(t *testing.T) {

	first := RegisterIP("203.0.113.10:54321")

	second := RegisterIP("203.0.113.10:60000")

	if first != second {
		t.Errorf("RegisterIP produced different keys for the same client on different ports: %q vs %q", first, second)
	}
}

func TestLoginCredential_SameClientDifferentPortsProducesTheSameKey(t *testing.T) {

	first := LoginCredential("bayu@example.com", "203.0.113.10:54321")

	second := LoginCredential("bayu@example.com", "203.0.113.10:60000")

	if first != second {
		t.Errorf("LoginCredential produced different keys for the same client on different ports: %q vs %q", first, second)
	}
}

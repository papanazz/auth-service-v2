package session

import "testing"

// The transport layer passes http.Request.RemoteAddr straight through, which
// always carries a port. Before this was handled, every session was stored with
// a NULL ip_address even though the value had been collected correctly.
func TestParseIP(t *testing.T) {

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
			name:  "bare IPv6",
			input: "2001:db8::1",
			want:  "2001:db8::1",
		},
		{
			name:  "loopback with port",
			input: "127.0.0.1:8080",
			want:  "127.0.0.1",
		},
		{
			name:  "empty value stores NULL",
			input: "",
			want:  "",
		},
		{
			name:  "unparseable value stores NULL rather than failing the login",
			input: "not-an-address",
			want:  "",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			got := parseIP(tt.input)

			if tt.want == "" {

				if got != nil {
					t.Fatalf("parseIP(%q) = %v, want nil", tt.input, got)
				}

				return
			}

			if got == nil {
				t.Fatalf("parseIP(%q) = nil, want %q", tt.input, tt.want)
			}

			if got.String() != tt.want {
				t.Errorf("parseIP(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

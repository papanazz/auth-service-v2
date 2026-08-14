package logger

import "testing"

func TestMaskEmail(t *testing.T) {

	tests := []struct {
		name string

		input string

		want string
	}{
		{
			name: "typical address keeps the first two local-part characters",

			input: "bayu.aditya@example.com",

			want: "ba***@example.com",
		},
		{
			name: "a one-character local part still keeps one character, not zero",

			input: "a@example.com",

			want: "a***@example.com",
		},
		{
			name: "a two-character local part keeps both",

			input: "ab@example.com",

			want: "ab***@example.com",
		},
		{
			name: "no @ at all falls back to a fixed mask, never the raw input",

			input: "not-an-email",

			want: "***",
		},
		{
			name: "empty local part before @ falls back to a fixed mask",

			input: "@example.com",

			want: "***",
		},
		{
			name: "empty string falls back to a fixed mask",

			input: "",

			want: "***",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if got := MaskEmail(tt.input); got != tt.want {
				t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// The domain must never be masked — it's useful for spotting a wave of
// abuse from one domain — but the full local part must never survive,
// whatever its length.
func TestMaskEmail_NeverReturnsTheFullLocalPart(t *testing.T) {

	email := "bayu.aditya.principal.engineer@example.com"

	got := MaskEmail(email)

	if got == email {
		t.Fatal("MaskEmail returned the input unmodified")
	}

	local := "bayu.aditya.principal.engineer"

	if len(got) >= len(local) && got[:len(local)] == local {
		t.Errorf("MaskEmail(%q) = %q, the full local part survived", email, got)
	}
}

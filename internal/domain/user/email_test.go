package user

import "testing"

func TestNormalizeEmail(t *testing.T) {

	tests := []struct {
		name string

		input string

		want string
	}{
		{
			name:  "lowercases and trims regardless of domain",
			input: "  Bayu.Aditya87@Example.COM  ",
			want:  "bayu.aditya87@example.com",
		},
		{
			name:  "gmail: dots in the local part are insignificant",
			input: "bayu.aditya87@gmail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "gmail: a +tag is discarded",
			input: "bayuaditya87+work@gmail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "gmail: dots and a +tag together",
			input: "bayu.aditya87+work@gmail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "gmail: a dot inside the +tag doesn't leak into the local part",
			input: "bayu.aditya87+news.letter@gmail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "gmail: casing and whitespace normalize the same as any other domain",
			input: "  Bayu.Aditya87+Work@GMAIL.COM  ",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "googlemail.com aliases to gmail.com, with the same dot/tag rules",
			input: "bayu.aditya87+work@googlemail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "an address already in canonical form is unchanged",
			input: "bayuaditya87@gmail.com",
			want:  "bayuaditya87@gmail.com",
		},
		{
			name:  "a non-gmail domain keeps its dots — they can be meaningful there",
			input: "First.Last@Company.com",
			want:  "first.last@company.com",
		},
		{
			name:  "a non-gmail domain keeps its +tag — no documented equivalence exists",
			input: "someone+tag@example.com",
			want:  "someone+tag@example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "malformed input with no @ is only lowercased and trimmed",
			input: "  NOT-AN-EMAIL  ",
			want:  "not-an-email",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if got := NormalizeEmail(tt.input); got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// The property that actually matters: every way of writing the same Gmail
// mailbox collapses to one identity, so registration can't be duplicated
// and login can't fail against a different-but-equivalent variation.
func TestNormalizeEmail_GmailVariationsConverge(t *testing.T) {

	variations := []string{
		"bayuaditya87@gmail.com",
		"bayu.aditya87@gmail.com",
		"b.a.y.u.a.d.i.t.y.a.8.7@gmail.com",
		"bayuaditya87+anything@gmail.com",
		"bayu.aditya87+anything@gmail.com",
		"BayuAditya87@Gmail.com",
		"  bayuaditya87@gmail.com  ",
		"bayuaditya87@googlemail.com",
		"bayu.aditya87+tag@GoogleMail.COM",
	}

	want := "bayuaditya87@gmail.com"

	for _, v := range variations {

		if got := NormalizeEmail(v); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", v, got, want)
		}
	}
}

// NormalizeEmail must be idempotent: applying it to its own output has to
// return the same value, since register normalizes on write and user.New
// normalizes again inside Create — if the function weren't idempotent,
// double-application could drift the stored value from what a
// single-application caller (e.g. a future consumer) would compute.
func TestNormalizeEmail_Idempotent(t *testing.T) {

	inputs := []string{
		"bayu.aditya87+work@gmail.com",
		"First.Last@Company.com",
		"",
		"not-an-email",
	}

	for _, in := range inputs {

		once := NormalizeEmail(in)

		twice := NormalizeEmail(once)

		if once != twice {
			t.Errorf("NormalizeEmail(%q) = %q, but normalizing again gave %q", in, once, twice)
		}
	}
}

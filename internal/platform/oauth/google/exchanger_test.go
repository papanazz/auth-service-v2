package google

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	domain "github.com/papanazz/auth-service-v2/internal/domain/oauth"
)

func TestExchanger_AuthCodeURL(t *testing.T) {

	exchanger := NewExchanger("client-id", "client-secret", "https://app.example.com/callback")

	authURL := exchanger.AuthCodeURL("the-state", "the-challenge")

	parsed, err := url.Parse(authURL)

	if err != nil {
		t.Fatalf("AuthCodeURL returned an unparseable URL: %v", err)
	}

	query := parsed.Query()

	tests := []struct {
		param string

		want string
	}{
		{"client_id", "client-id"},
		{"redirect_uri", "https://app.example.com/callback"},
		{"state", "the-state"},
		{"code_challenge", "the-challenge"},
		{"code_challenge_method", "S256"},
	}

	for _, tt := range tests {

		if got := query.Get(tt.param); got != tt.want {
			t.Errorf("%s = %q, want %q", tt.param, got, tt.want)
		}
	}
}

// testServer stands in for Google's token endpoint and userinfo
// endpoint at once — Exchange talks to both in sequence, so both need
// to be reachable at the same base URL an Exchanger under test is
// pointed at.
func testServer(
	t *testing.T,
	userInfo map[string]any,
	userInfoStatus int,
) *httptest.Server {

	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		if err := r.ParseForm(); err != nil {
			t.Fatalf("token request: parse form: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {

		if auth := r.Header.Get("Authorization"); auth != "Bearer test-access-token" {

			t.Errorf("userinfo request Authorization = %q, want the access token from the exchange", auth)
		}

		if userInfoStatus != 0 && userInfoStatus != http.StatusOK {

			w.WriteHeader(userInfoStatus)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(userInfo)
	})

	return httptest.NewServer(mux)
}

func newTestExchanger(server *httptest.Server) *Exchanger {

	exchanger := NewExchanger("client-id", "client-secret", "https://app.example.com/callback")

	exchanger.config.Endpoint.TokenURL = server.URL + "/token"

	exchanger.userInfoURL = server.URL + "/userinfo"

	return exchanger
}

func TestExchanger_Exchange(t *testing.T) {

	server := testServer(t, map[string]any{
		"sub":            "google-sub-1",
		"email":          "bayu@example.com",
		"email_verified": true,
		"name":           "Bayu",
	}, http.StatusOK)

	defer server.Close()

	exchanger := newTestExchanger(server)

	identity, err := exchanger.Exchange(context.Background(), "auth-code", "the-verifier")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := domain.Identity{

		Provider: domain.ProviderGoogle,

		ProviderUserID: "google-sub-1",

		Email: "bayu@example.com",

		EmailVerified: true,

		Name: "Bayu",
	}

	if identity != want {
		t.Errorf("identity = %+v, want %+v", identity, want)
	}
}

func TestExchanger_Exchange_SendsTheCodeVerifier(t *testing.T) {

	var seenVerifier, seenCode string

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		seenVerifier = r.FormValue("code_verifier")

		seenCode = r.FormValue("code")

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "google-sub-1",
		})
	})

	server := httptest.NewServer(mux)

	defer server.Close()

	exchanger := newTestExchanger(server)

	_, err := exchanger.Exchange(context.Background(), "the-code", "the-verifier")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if seenCode != "the-code" {
		t.Errorf("token request code = %q, want %q", seenCode, "the-code")
	}

	if seenVerifier != "the-verifier" {
		t.Errorf("token request code_verifier = %q, want %q — PKCE only holds if this reaches the token endpoint", seenVerifier, "the-verifier")
	}
}

func TestExchanger_Exchange_TokenExchangeFailure(t *testing.T) {

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusBadRequest)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_grant",
		})
	})

	server := httptest.NewServer(mux)

	defer server.Close()

	exchanger := newTestExchanger(server)

	_, err := exchanger.Exchange(context.Background(), "bad-code", "the-verifier")

	if err == nil {
		t.Fatal("expected an error for a rejected authorization code")
	}
}

func TestExchanger_Exchange_UserInfoFailure(t *testing.T) {

	server := testServer(t, nil, http.StatusUnauthorized)

	defer server.Close()

	exchanger := newTestExchanger(server)

	_, err := exchanger.Exchange(context.Background(), "auth-code", "the-verifier")

	if err == nil {
		t.Fatal("expected an error when the userinfo endpoint rejects the access token")
	}
}

func TestExchanger_Exchange_UserInfoMalformedResponse(t *testing.T) {

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write([]byte(strings.Repeat("{", 3)))
	})

	server := httptest.NewServer(mux)

	defer server.Close()

	exchanger := newTestExchanger(server)

	_, err := exchanger.Exchange(context.Background(), "auth-code", "the-verifier")

	if err == nil {
		t.Fatal("expected an error for a malformed userinfo response")
	}
}

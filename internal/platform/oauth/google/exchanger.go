package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	domain "github.com/papanazz/auth-service-v2/internal/domain/oauth"
)

// defaultUserInfoURL is Google's OIDC userinfo endpoint — called with
// the access token from a completed exchange, over a direct HTTPS
// connection to Google, so its email/email_verified/sub claims can be
// trusted without a separate JWT signature verification step.
const defaultUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

var _ domain.Exchanger = (*Exchanger)(nil)

type Exchanger struct {
	config *oauth2.Config

	// userInfoURL is a field, not a constant, purely so a test can
	// point it at an httptest.Server instead of the real Google
	// endpoint.
	userInfoURL string
}

func NewExchanger(
	clientID string,
	clientSecret string,
	redirectURL string,
) *Exchanger {

	return &Exchanger{

		config: &oauth2.Config{

			ClientID: clientID,

			ClientSecret: clientSecret,

			RedirectURL: redirectURL,

			Scopes: []string{
				"openid",
				"email",
				"profile",
			},

			Endpoint: googleoauth.Endpoint,
		},

		userInfoURL: defaultUserInfoURL,
	}
}

func (e *Exchanger) AuthCodeURL(
	state string,
	codeChallenge string,
) string {

	return e.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (e *Exchanger) Exchange(
	ctx context.Context,
	code string,
	codeVerifier string,
) (
	domain.Identity,
	error,
) {

	token, err :=
		e.config.Exchange(
			ctx,
			code,
			oauth2.SetAuthURLParam("code_verifier", codeVerifier),
		)

	if err != nil {
		return domain.Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}

	// e.config.Client wraps http.DefaultClient with the token's Bearer
	// header attached automatically — a direct, authenticated call to
	// Google, not something the browser or the authorization code
	// touches again.
	client := e.config.Client(ctx, token)

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			e.userInfoURL,
			nil,
		)

	if err != nil {
		return domain.Identity{}, fmt.Errorf("build userinfo request: %w", err)
	}

	resp, err := client.Do(req)

	if err != nil {
		return domain.Identity{}, fmt.Errorf("call userinfo endpoint: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return domain.Identity{}, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var body struct {
		Sub string `json:"sub"`

		Email string `json:"email"`

		EmailVerified bool `json:"email_verified"`

		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.Identity{}, fmt.Errorf("decode userinfo response: %w", err)
	}

	return domain.Identity{

		Provider: domain.ProviderGoogle,

		ProviderUserID: body.Sub,

		Email: body.Email,

		EmailVerified: body.EmailVerified,

		Name: body.Name,
	}, nil
}

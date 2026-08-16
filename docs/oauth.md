# OAuth (Sign in with Google)

`GET /v1/auth/oauth/{provider}/start`
`GET /v1/auth/oauth/{provider}/callback`

OAuth **client** login — this service is the relying party, never an
authorization server. `{provider}` is a URL path segment; `google` is
the only value accepted today (see Gaps). Architecture and the
account-linking policy were decided up front in
`docs/adr/0001-oauth-client-and-account-linking.md`; this document is
the implementation record — read the ADR first for the *why*, this file
for the *how*.

## Flow

### `/start` — `internal/app/auth/oauthstart/service.go`

1. **Validate input.** Non-empty `device_id`, a known `device_type`
   (`WEB`/`ANDROID`/`IOS`) — checked here, not deferred to the callback,
   since these values travel inside the state payload untouched and
   Google's own redirect can't carry a corrected value back.
2. **Generate `state` and a PKCE pair** (`domain/oauth.Generator`):
   32 random bytes each, base64 `RawURLEncoding`; the PKCE challenge is
   `SHA256(verifier)`, also base64 `RawURLEncoding` (S256, per RFC
   7636).
3. **Store the state record** (`oauth.StateStore`, Redis, TTL
   `OAUTH_STATE_TTL`): `{code_verifier, device_id, device_name,
   device_type}` keyed by `state` — this is the only place
   `device_id`/`device_name`/`device_type` survive between `/start` and
   `/callback`, since Google's redirect only ever appends `?code=&state=`.
4. Return `{auth_url}` — the client redirects the user's browser there.

### `/callback` — `internal/app/auth/oauthcallback/service.go`

1. **Consume the state** (`StateStore.Consume`, Redis `GETDEL` —
   atomic, single-use). Not found (unknown, expired, or already
   consumed — indistinguishable by design) → `INVALID_OAUTH_STATE`.
2. **Redeem the authorization code** (`oauth.Exchanger.Exchange`):
   token exchange against Google with the PKCE verifier from the state
   payload, then a call to Google's own OIDC userinfo endpoint with the
   resulting access token — see Decisions for why this service reads
   claims from userinfo rather than parsing/verifying the ID token JWT
   itself.
3. **Resolve the identity** — the three-case account-linking policy
   below.
4. **Issue the session** (`sessionissuer.Issuer.IssueForDevice`) — the
   exact transactional logic login uses (device-slot lock,
   supersede-within-grace-period, session + refresh token creation), not
   a second copy of it. See Decisions.
5. Return `{access_token, refresh_token, expires_in}` — identical shape
   to `login.Result`.

### Account-linking policy

Evaluated in order, once `oauth.Repository.FindByProviderID(provider,
provider_user_id)` has answered whether this identity is already
linked:

1. **Already linked** → log in as the linked account (after the same
   `CanLogin` gate login itself applies).
2. **Not linked, and no `users` row has `Identity.Email`** →
   auto-register: `user.NewOAuth(email)`, `Status` forced `ACTIVE`
   (mirrors register's own reasoning — see `docs/register.md`
   Decisions). If the provider asserts `email_verified`,
   `EmailVerifiedAt` is set immediately; otherwise the account falls
   back to the ordinary email-verification flow (a token is minted,
   cached, and emailed — logic deliberately duplicated from
   `register.Service`, not extracted, since the two call sites diverge
   enough that a shared component would be premature for one reuse).
   The account row, the `oauth_identities` link, and (when needed) the
   verification token are created in one transaction.
3. **Not linked, but a `users` row already has `Identity.Email`** —
   both sides must be verified to proceed:
   - `Identity.EmailVerified` **and** the existing account's own
     `EmailVerifiedAt` → auto-link (`oauth_identities` row created) and
     log in. Linking happens before the `CanLogin` gate — a locked
     account still gets linked, it just doesn't get a session this time
     around (see Tested Scenarios).
   - Either side unverified → reject with `USER_ALREADY_EXISTS` (409),
     the same error/status register already uses for a duplicate email.
     No link is created.

Since `users.email` is unique, these three cases are exhaustive — see
the ADR for the full security rationale.

## Decisions

- **Userinfo endpoint over ID-token verification.** `platform/oauth/google`
  calls `https://openidconnect.googleapis.com/v1/userinfo` with the
  access token from a completed exchange rather than parsing and
  verifying the ID token JWT's signature locally. The HTTPS connection
  to Google *is* the trust boundary here — an access token obtained by
  the direct, server-to-server exchange call can only have come from
  Google — so a separate JWKS-fetch-and-verify step would add
  complexity without adding security for this use case.

- **Both sides must be verified to auto-link** (case 3). Requiring only
  the provider's assertion would let anyone who controls an email
  address transiently (e.g. a lapsed domain, a provider bug) take over
  an existing account by signing up for OAuth with that address.
  Requiring only the local `EmailVerifiedAt` would trust every future
  OAuth provider's verification claim unconditionally. Requiring both
  closes both gaps — see the ADR's Consequences section for the full
  argument; this is called out there as "load-bearing and easy to
  accidentally drop."

- **Session issuance is shared, not reimplemented.** `sessionissuer.Issuer`
  was extracted out of `login.Service` (which used to inline this logic
  in its own flow steps 6-7) specifically so OAuth login could not drift
  from password login's session-minting behavior. `login.Service` and
  `oauthcallback.Service` hold the same `*sessionissuer.Issuer` instance
  in `app.go`. See `docs/login.md` for the device-slot/grace-period
  mechanics themselves — unchanged by the extraction, verified by
  login's full pre-existing test suite (including its 16-goroutine
  concurrency test) passing unmodified against the extracted code.

- **`password_hash` is nullable.** An OAuth-only account has no
  password at all. `login.Service` gates on this explicitly before
  dereferencing: a nil hash runs the same dummy-Argon2-verification path
  as an unknown account and returns `INVALID_CREDENTIALS`, never a
  different error that would reveal "this account has no password" —
  the same enumeration-safety stance login already applied to unknown
  accounts, just extended to cover this case too.

- **Linking happens before the `CanLogin` gate** (case 1 and case 3).
  The identity link is a durable fact about the account, independent of
  whether this particular sign-in attempt is allowed to proceed — a
  locked account that completes a valid OAuth round trip still gets
  linked, it's just denied a session, exactly like a correct password
  against a locked account in `login.Service`.

- **No separate authenticated "link an account" flow.** Considered and
  deliberately dropped (see the ADR) in favor of the single auto-link
  policy above — one flow to reason about and test, at the cost of no
  way to link an account whose email doesn't match what's on file (see
  Gaps).

- **The `{provider}` path segment exists for future extensibility, not
  present-day dispatch.** `handler/oauth.go` checks it equals `google`
  and rejects anything else with `OAUTH_PROVIDER_UNSUPPORTED` — there is
  exactly one `oauth.Exchanger` wired in `app.go`, not a
  provider-keyed registry, since a second provider doesn't exist yet to
  design that registry around.

## Capabilities

- PKCE (S256), per RFC 7636 — the authorization code alone is never
  sufficient to complete the exchange.
- Single-use, TTL-bound `state` (Redis `GETDEL`) — replay of a captured
  callback URL fails with the same `INVALID_OAUTH_STATE` an expired or
  unknown state would, both live-verified (see Tested Scenarios).
- Device identity (`device_id`/`device_name`/`device_type`) carried
  through the redirect via the state payload, validated up front in
  `/start` exactly like `login.Validate` validates it.
- Auto-registration, auto-login, and auto-linking collapse into the
  single-request `/callback` round trip — no separate "finish setting
  up your account" step for the common cases.
- Full audit trail: `LOGIN_SUCCESS`/`LOGIN_FAILED` (shared with login,
  since from the audit trail's point of view OAuth login is not a
  different kind of login), `USER_REGISTERED` (shared with register),
  and the one genuinely new event type, `OAUTH_ACCOUNT_LINKED`, for the
  case-3 auto-link only.
- Shares login's device-session-conflict handling
  (`DEVICE_SESSION_ALREADY_ACTIVE`) and account-status gate
  (`ACCOUNT_LOCKED`) via the same `sessionissuer.Issuer` and the same
  `CanLogin()` check.

## Gaps

- **Google only.** `domain/oauth.Provider` and the `{provider}` path
  segment are shaped for more than one provider, but only
  `platform/oauth/google` exists, and `app.go` wires exactly one
  `oauth.Exchanger` into both use cases. Adding a second provider means
  a second `Exchanger` implementation plus provider-keyed dispatch in
  `handler/oauth.go` and `app.go` — not done, since there's no second
  provider to design that dispatch around yet.

- **No unlinking flow.** Once an `oauth_identities` row exists there is
  no endpoint to remove it — not a security gap (removal has no attack
  surface of its own), just a feature that hasn't been asked for.

- **No path to link an account under a non-matching email.** Case 3
  only fires when the provider's email matches an existing account's
  email exactly; a user who wants to link a Google account whose email
  differs from their registered email has no supported flow (this is
  exactly the "separate authenticated link flow" the ADR describes
  dropping — deliberately out of scope for now, not overlooked).

- **This environment has no real Google OAuth application registered**
  (see Tested Scenarios) — `/start` and `/callback` are both live and
  correctly wired end-to-end up to the point of actually reaching
  Google's real token endpoint with real credentials, which needs an
  app registration only a deployer can provide
  (`GOOGLE_OAUTH_CLIENT_ID`/`_SECRET`/`_REDIRECT_URL`).

## API Contract

**`GET /v1/auth/oauth/{provider}/start`**

```
GET /v1/auth/oauth/google/start?device_id=...&device_name=...&device_type=WEB
```

| Param | Required | Notes |
|---|---|---|
| `device_id` | yes | non-empty |
| `device_name` | no | |
| `device_type` | yes | one of `WEB` \| `ANDROID` \| `IOS` |

**Success — `200 OK`**

```json
{ "data": { "auth_url": "https://accounts.google.com/o/oauth2/auth?..." } }
```

**`GET /v1/auth/oauth/{provider}/callback`**

```
GET /v1/auth/oauth/google/callback?code=...&state=...
```

Called by Google's redirect, not by the client directly.

**Success — `200 OK`**

```json
{
  "data": {
    "access_token": "jwt",
    "refresh_token": "opaque-raw-token",
    "expires_in": 900
  }
}
```

**Errors** (both endpoints)

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | `/start`: empty `device_id` or unknown `device_type`. `/callback`: missing `code` or `state` |
| 400 | `OAUTH_PROVIDER_UNSUPPORTED` | `{provider}` is not `google` |
| 400 | `INVALID_OAUTH_STATE` | unknown, expired, or already-consumed `state` |
| 403 | `ACCOUNT_LOCKED` | resolved account fails `CanLogin()` |
| 409 | `USER_ALREADY_EXISTS` | email collision, either side unverified |
| 409 | `DEVICE_SESSION_ALREADY_ACTIVE` | active session on this device, outside the grace period |
| 500 | `INTERNAL_ERROR` | unexpected failure, including a real exchange failure against Google |

No authentication required for either endpoint.

## Tested Scenarios

Unit — `internal/app/auth/oauthstart/service_test.go`
(`go test ./internal/app/auth/oauthstart/... -race`):

- starts the flow and returns a non-empty auth URL
- rejects an empty/blank `device_id` and an unknown `device_type`
  before touching any dependency
- the stored state payload carries the command's own
  `device_id`/`device_name`/`device_type` and the generated code
  verifier
- the auth URL is built from the generated state and PKCE challenge
- propagates a state-generation, PKCE-generation, or state-store
  failure

Unit — `internal/app/auth/oauthcallback/service_test.go`
(`go test ./internal/app/auth/oauthcallback/... -race`):

- rejects empty `code`/`state` before consuming any state
- rejects an unknown/expired/already-consumed state;  propagates a
  state-store failure
- propagates an exchange failure; the code and PKCE verifier reaching
  `Exchange` are exactly the ones from the request and the state
  payload
- case 1 (linked identity): logs in the linked account, session carries
  the state payload's device fields, `UpdateLastLoginAt` called once,
  audited `LOGIN_SUCCESS`; propagates a lookup failure for the linked
  account and an unexpected link-lookup failure; a locked linked
  account is rejected with no session created, audited `LOGIN_FAILED`;
  an active session on the same device is rejected and audited the
  same way login's own device-conflict case is
- case 2 (auto-register): a provider-verified email skips the
  verification flow (`EmailVerifiedAt` set, no token issued, account
  has no password hash); an unverified provider email falls back to
  minting/caching/emailing a verification token; the `oauth_identities`
  link is created in the same transaction as the account; audits
  `USER_REGISTERED` then `LOGIN_SUCCESS`; a transaction failure
  propagates and audits nothing; an unexpected email-lookup failure
  propagates
- case 3 (email collision): both sides verified auto-links and logs in,
  audited `OAUTH_ACCOUNT_LINKED` then `LOGIN_SUCCESS`; either side
  unverified rejects with `USER_ALREADY_EXISTS` and creates no link
  (tested for both the provider-unverified and account-unverified
  sub-cases); a locked-but-otherwise-eligible account still gets
  linked, just denied a session

Unit — `internal/platform/oauth/google/exchanger_test.go`
(`go test ./internal/platform/oauth/google/... -race`), against an
`httptest.Server` standing in for both Google endpoints:

- `AuthCodeURL` carries `client_id`, `redirect_uri`, `state`,
  `code_challenge`, and `code_challenge_method=S256`
- a successful exchange maps the userinfo response's
  `sub`/`email`/`email_verified`/`name` onto `domain/oauth.Identity`
  correctly, `Provider` set to `ProviderGoogle`
- the `code` and `code_verifier` the token endpoint receives are
  exactly the ones passed to `Exchange`
- a rejected authorization code (token endpoint 400), a userinfo
  endpoint failure (401), and a malformed userinfo JSON response all
  return an error

Unit — `internal/app` (`go test ./internal/app/... -run TestNew`):
`newOAuthStartPolicy`/`newOAuthCallbackPolicy` wire every field
(reflection-based regression test — see `docs/login.md`'s equivalent
for `newLoginSecurityPolicy`), and carry the configured
`OAUTH_STATE_TTL`/`EMAIL_VERIFICATION_TOKEN_TTL` values through
correctly.

Regression — `internal/app/auth/login/...` and
`internal/app/user/register/...` full suites re-run unmodified after
the `sessionissuer` extraction and the `PasswordHash *string` change;
all pass under `-race`.

e2e — against the real docker-compose stack, without a real Google
OAuth application registered (`GOOGLE_OAUTH_CLIENT_ID`/`_SECRET` blank):

- `GET /v1/auth/oauth/facebook/start` and `.../facebook/callback` → 400
  `OAUTH_PROVIDER_UNSUPPORTED`
- `GET /v1/auth/oauth/google/start` with no `device_id` → 400
  `INVALID_REQUEST`; with valid params → 200, well-formed `auth_url`
  containing the generated `state`/`code_challenge`
- `GET /v1/auth/oauth/google/callback` with no `code`/`state` → 400
  `INVALID_REQUEST`; with an unknown `state` → 400 `INVALID_OAUTH_STATE`
- a real `state` minted by `/start`, replayed against `/callback` twice:
  the first call consumes it and fails at Google's real token endpoint
  (500, logged with Google's own `"Could not determine client ID from
  request"` — proof the exchange call reaches Google for real, it just
  has no credentials to present); the second call with the same
  now-consumed `state` correctly returns 400 `INVALID_OAUTH_STATE`,
  confirming the Redis `GETDEL` single-use consumption round-trips
  correctly against real Redis
- `oauth_identities` table and the nullable `users.password_hash`
  column confirmed present with the expected shape via `psql \d`
  against the live database
- register → login full lifecycle re-verified live after the
  `sessionissuer` extraction: unaffected

## Related Files

```
internal/app/auth/oauthstart/service.go        use case
internal/app/auth/oauthstart/service_test.go
internal/app/auth/oauthcallback/service.go      use case, 3-case policy
internal/app/auth/oauthcallback/event.go        LOGIN_*/USER_REGISTERED/
                                                 OAUTH_ACCOUNT_LINKED constructors
internal/app/auth/oauthcallback/validator.go
internal/app/auth/oauthcallback/policy.go       SecurityPolicy shape
internal/app/auth/oauthcallback/service_test.go
internal/app/auth/sessionissuer/issuer.go       shared session-minting logic
internal/app/policy.go                          config -> SecurityPolicy
internal/domain/oauth/                          Provider, Identity, Exchanger,
                                                 Link, Repository, StateStore,
                                                 Generator, StatePayload
internal/domain/user/user.go                    PasswordHash *string, NewOAuth
internal/domain/audit/event.go                  EventOAuthAccountLinked
internal/platform/oauth/google/exchanger.go     Google Exchanger implementation
internal/platform/oauth/generator.go            RandomGenerator (state + PKCE)
internal/platform/oauthstate/store.go           Redis-backed StateStore
internal/platform/postgres/repository/oauthidentity/   Postgres Repository
internal/platform/postgres/repository/user/repository.go
                                                 pgTextFromPointer/pointerFromPgText
internal/platform/errs/oauth.go                 ErrOAuthIdentityNotFound
internal/platform/errs/code.go                  CodeInvalidOAuthState,
                                                 CodeOAuthProviderUnsupported
internal/platform/errs/domain.go                ErrInvalidOAuthState,
                                                 ErrOAuthProviderUnsupported
internal/transport/http/handler/oauth.go        HTTP handlers
internal/transport/http/router.go               GET /v1/auth/oauth/{provider}/start,
                                                 .../callback
internal/platform/config/config.go              OAUTH_STATE_TTL,
                                                 GOOGLE_OAUTH_CLIENT_ID/_SECRET/_REDIRECT_URL
migrations/000010_add_oauth_support.up.sql      oauth_identities table,
                                                 nullable password_hash
queries/oauth_identity.sql                      hand-written SQL, sqlc source
docs/adr/0001-oauth-client-and-account-linking.md   architecture + policy record
```

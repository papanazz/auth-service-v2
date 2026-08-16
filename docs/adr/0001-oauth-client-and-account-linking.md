# ADR 0001: OAuth Client Integration and Account-Linking Policy

**Status:** Accepted
**Date:** 2026-08-16

## Context

`auth-service-v2` currently supports one identity method: email + password
(`docs/register.md`, `docs/login.md`). We want to add "Sign in with
Google" as a second method, extensible to other providers later, without
replacing or weakening the first.

"OAuth" covers two unrelated things and this ADR is scoped to exactly
one of them:

- **OAuth client** (relying party) — this service consumes a third
  party's identity assertion to authenticate a user. This is what
  "Sign in with Google" means, and it's what this ADR covers.
- **OAuth provider** (authorization server) — this service would issue
  tokens to third-party apps acting on a user's behalf (RFC 6749
  `/authorize` + `/token`, client registration, consent screens). Out of
  scope entirely; nothing here should be read as a step toward it.

The two things that make this more than a mechanical integration:
`users.password_hash` is currently `NOT NULL` (`migrations/000003_create_users.up.sql`),
which an OAuth-only account (no password ever set) can't satisfy — and
an OAuth identity's email can collide with an *existing* password
account's email, which is the classic OAuth account-takeover vector if
handled carelessly.

## Decision

### Architecture

Follows the existing `domain`/`app`/`platform`/`transport` layering and
one-package-per-use-case convention exactly — no new patterns introduced
for this feature.

- **`internal/domain/oauth`** — a provider-agnostic `Exchanger`
  interface (`AuthCodeURL(state, codeChallenge string) string`,
  `Exchange(ctx, code, codeVerifier string) (Identity, error)`) and an
  `Identity` value object (`Provider`, `ProviderUserID`, `Email`,
  `EmailVerified bool`, `Name`). The app layer never sees a
  Google-specific shape, the same separation `domain/password.Hasher`
  already gives Argon2id.
- **`internal/platform/oauth/google`** — the concrete adapter, built on
  `golang.org/x/oauth2` rather than a hand-rolled token exchange.
  Google is the first provider; a second provider is a second package
  behind the same `Exchanger` interface, not a rewrite.
- **New table, `oauth_identities`**: `id`, `user_id` (FK, `ON DELETE
  CASCADE`), `provider`, `provider_user_id`, `email`, `created_at`,
  `UNIQUE(provider, provider_user_id)` — the standard linked-accounts
  pattern. `users.password_hash` becomes nullable: an OAuth-only account
  has none. `login.Service`'s password-verification step needs an
  explicit guard for a `NULL` hash — it must fail closed into the same
  `ErrInvalidCredentials` a wrong password produces, not panic on a nil
  dereference, and not reveal "this account has no password" (the same
  enumeration-safety stance `docs/login.md` already documents for
  unknown accounts).
- **New use cases**: `app/auth/oauthstart` builds the authorization URL
  — generates `state` and a PKCE `code_verifier`, stores
  `{state -> code_verifier}` in Redis with a short TTL, single-use
  (mirrors the existing idempotency store's claim pattern, see
  `docs/login.md` Idempotency). `app/auth/oauthcallback` validates and
  consumes `state`, exchanges the code, then does exactly one of: log in
  an already-linked user, register a brand-new account (no email
  collision), or link the identity to the current authenticated user
  (see Account-Linking Policy below).
- **Session issuance is not reimplemented.** The transactional "create a
  session + refresh token for this account+device" step currently lives
  inside `login.Service.Handle` (`internal/app/auth/login/service.go`
  flow step 7). This gets extracted into a shared component both `login`
  and `oauthcallback` call, so there is exactly one implementation of
  session minting — two auth methods with independently-evolving session
  logic is how they drift apart in security posture.
- **Transport**: `GET /v1/auth/oauth/{provider}/start` (anonymous —
  login/register intent) and `GET /v1/user/oauth/{provider}/link/start`
  (requires an authenticated session — link intent) both funnel into one
  `GET /v1/auth/oauth/{provider}/callback`. The handler branches on
  whether the `state` record it consumed carries a `user_id` — that's
  what distinguishes "this callback is a link" from "this callback is a
  login/register," not a separate callback path per intent.

### Account-linking policy

**A first-time OAuth identity is linked to an account only from an
authenticated session that the user themselves initiated** — by visiting
`/v1/user/oauth/{provider}/link/start` while already logged in. It is
**never** linked automatically at anonymous first sign-in, even when the
provider's email matches an existing account and the provider asserts
`email_verified: true`.

If an anonymous OAuth callback's email collides with an existing,
not-yet-linked account, the service returns `errs.ErrUserAlreadyExists`
(`409`, `"user already exists"`) — the identical error register already
returns for a duplicate-email registration attempt (`docs/register.md`),
deliberately reused rather than minting an OAuth-specific code. The
client-visible outcome is the same shape as an existing, well-understood
failure mode; no new error taxonomy for this feature.

When there's **no** email collision, a new account is created following
the same conventions `register.Service` already establishes:
`Status = ACTIVE` immediately (`docs/register.md` Decisions), and
`email_verified_at` set immediately *only if* the provider asserted the
email verified — otherwise the account falls through to the existing
email-verification flow untouched (`docs/email-verification.md`), with
no OAuth-specific verification path invented.

## Consequences

**Positive:**

- Closes the classic OAuth account-takeover vector entirely — auto-linking
  on email match is exactly how an attacker who can get *any* email
  verified by an IdP (their own Google Workspace domain, a compromised
  mailbox, or simply the provider's own weaker verification bar) takes
  over a same-email account created a different way. Requiring an
  authenticated session to link removes that path structurally, not by
  policy that could be gotten wrong at one call site and not another.
- Zero duplicated security logic: session minting, the `ACTIVE` status
  convention, and the email-verification flow are all reused as-is
  rather than re-implemented for the OAuth path.
- The collision error is something a client already knows how to render
  — it's register's existing `409 USER_ALREADY_EXISTS`, not a new case
  to handle.

**Negative / accepted trade-offs:**

- Worse first-time UX for a legitimate user who already has a password
  account under the same email: they see `"user already exists"` from
  the OAuth attempt and have to log in with their original method, then
  separately visit the link flow — no silent, one-click merge. This is
  the deliberate cost of closing the takeover vector, not an oversight.
- `users.password_hash` going nullable is a real schema change touching
  every existing read of that column (`docs/login.md` password
  verification, any future admin/support tooling) — worth flagging
  again at implementation time, not just here.
- No account-unlinking flow is specified by this ADR — an account that
  links a provider has no documented way to remove it. Deferred as a
  smaller, separable follow-up once linking itself exists.

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
account's email, which needs a deliberate policy, not an accident of
whatever the code happens to do first.

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
- **One use case, `app/auth/oauthcallback`**, not two. There's no
  separate authenticated "link a provider" flow (considered and
  deliberately dropped — see Consequences): every OAuth sign-in is
  anonymous and goes through the same decision in Account-Linking Policy
  below. `app/auth/oauthstart` builds the authorization URL — generates
  `state` and a PKCE `code_verifier`, stores `{state -> code_verifier}`
  in Redis with a short TTL, single-use (mirrors the existing
  idempotency store's claim pattern, see `docs/login.md` Idempotency).
- **Session issuance is not reimplemented.** The transactional "create a
  session + refresh token for this account+device" step currently lives
  inside `login.Service.Handle` (`internal/app/auth/login/service.go`
  flow step 7). This gets extracted into a shared component both `login`
  and `oauthcallback` call, so there is exactly one implementation of
  session minting — two auth methods with independently-evolving session
  logic is how they drift apart in security posture.
- **Transport**: `GET /v1/auth/oauth/{provider}/start` and
  `GET /v1/auth/oauth/{provider}/callback`. Both anonymous — no
  authenticated variant.

### Account-linking policy

Three cases, evaluated in this order once the code has been exchanged
for an `Identity`:

1. **`oauth_identities` already has a row for `(provider, provider_user_id)`.**
   Returning user — log in as the linked account. (Ordinary case,
   unaffected by anything below.)
2. **No existing link, and no `users` row has `Identity.Email`.**
   No collision — auto-register a new account, same conventions
   `register.Service` already establishes: `Status = ACTIVE`
   immediately (`docs/register.md` Decisions), `email_verified_at` set
   immediately if-and-only-if `Identity.EmailVerified` is true —
   otherwise the account falls through to the existing
   email-verification flow untouched (`docs/email-verification.md`).
   Create the `oauth_identities` row, log in.
3. **No existing link, but a `users` row already has `Identity.Email`.**
   This is the collision case, and it splits in two:
   - **Both sides verified** — `Identity.EmailVerified` is true *and*
     the existing account's `email_verified_at` is already set — **auto-link**:
     create the `oauth_identities` row against that account, log in.
     Requiring *both* signals, not just one, is the load-bearing part of
     this policy — see Consequences for why.
   - **Either side is not verified** — reject with
     `errs.ErrUserAlreadyExists` (`409`, `"user already exists"`), the
     identical error register already returns for a duplicate-email
     registration attempt. No new error taxonomy for this feature. There
     is no third option here: `users.email` is unique, so a second
     account under the same address was never on the table.

## Consequences

**Positive:**

- A legitimate returning user whose Google email matches their existing,
  already-verified account gets a one-step, no-friction sign-in — the
  auto-link case is the common path, not the exception, which is what
  makes "Sign in with Google" actually convenient instead of a second
  registration wearing a different hat.
- Zero duplicated security logic: session minting, the `ACTIVE` status
  convention, and the email-verification flow are all reused as-is
  rather than re-implemented for the OAuth path.
- One use case, one transport flow, no authenticated/anonymous branch to
  keep in sync — considered and dropped (see below), which is real
  scope removed, not scope deferred.

**Negative / accepted trade-offs:**

- **Requiring the provider's `email_verified` claim, not just our own
  `email_verified_at`, is load-bearing and easy to accidentally drop.**
  Our own flag only proves *someone, once* controlled that mailbox
  during registration; it says nothing about who's authenticating right
  now. The provider's claim is what proves *today's* requester controls
  it. Checking only our side would mean any OAuth provider that ever
  asserts an unverified or spoofable email — a future addition, a
  misconfiguration, not necessarily Google itself — could log in as any
  existing verified account by claiming its address. Both checks stay
  required; this is the one place in this ADR future changes need to
  read carefully before "simplifying."
- **No path exists to link a provider whose email doesn't match the
  user's registered email**, or to link before the account is verified.
  Considered building a separate authenticated `/link` flow for this and
  deliberately cut for now — smaller initial surface, and the case is
  self-resolving (verify the account, or sign in with matching email)
  rather than blocked. Revisit as a separate ADR if real usage shows
  this gap matters.
- `users.password_hash` going nullable is a real schema change touching
  every existing read of that column (`docs/login.md` password
  verification, any future admin/support tooling) — worth flagging
  again at implementation time, not just here.
- No account-unlinking flow is specified by this ADR — an account that
  links a provider has no documented way to remove it. Deferred with
  the same reasoning as the missing link flow above.

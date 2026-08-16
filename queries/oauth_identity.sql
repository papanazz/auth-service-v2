-- =====================================================
-- Create OAuth Identity
--
-- Links a third-party identity to an account. The unique
-- constraint on (provider, provider_user_id) is the real
-- guarantee — this insert failing on conflict means the
-- identity is already linked, which the caller should
-- never hit given the FindByProviderID check that always
-- precedes it (see docs/oauth.md).
-- =====================================================


-- name: CreateOAuthIdentity :one

INSERT INTO oauth_identities (

    id,

    user_id,

    provider,

    provider_user_id,

    email

)

VALUES (

    $1,

    $2,

    $3,

    $4,

    $5

)

RETURNING *;



-- =====================================================
-- Find OAuth Identity By Provider
--
-- The lookup that decides which of the three account-linking
-- cases applies (docs/adr/0001-oauth-client-and-account-linking.md):
-- a row here means a returning user, no row means either a
-- brand-new account or an email collision to resolve.
-- =====================================================


-- name: GetOAuthIdentityByProviderID :one

SELECT *

FROM oauth_identities

WHERE provider = $1

AND provider_user_id = $2;

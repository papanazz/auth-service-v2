-- =====================================================
-- OAuth client support
--
-- password_hash becomes nullable: an account created via
-- an OAuth provider (see docs/oauth.md) may never have a
-- password at all. login's password-verification step
-- guards this explicitly rather than treating NULL as an
-- empty password.
--
-- oauth_identities links one or more third-party identities
-- to a user account. UNIQUE(provider, provider_user_id) is
-- the real integrity guarantee — the same provider identity
-- can never be linked to two different accounts.
-- =====================================================

ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

CREATE TABLE oauth_identities (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    provider VARCHAR(32) NOT NULL,

    provider_user_id VARCHAR(255) NOT NULL,

    email VARCHAR(255) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    UNIQUE(provider, provider_user_id)

);

CREATE INDEX idx_oauth_identities_user_id
ON oauth_identities(user_id);

-- =====================================================
-- Table: refresh_tokens
--
-- Definition:
-- Stores refresh token lifecycle information.
--
-- Security:
--
-- IMPORTANT:
-- Raw refresh tokens are NEVER stored.
--
-- Only SHA256 hashes are persisted.
--
--
-- Supports:
--
-- - Refresh token rotation
-- - Token family tracking
-- - Replay attack detection
-- - Token revocation
--
--
-- Lifecycle example:
--
-- Login
--   |
--   v
-- Token A
--   |
-- refresh
--   |
--   v
-- Token B
--   |
-- refresh
--   |
--   v
-- Token C
--
--
-- All tokens belong to the same family.
--
-- =====================================================


CREATE TABLE refresh_tokens (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    -- Authentication session owner.
    --
    -- One session may have multiple
    -- refresh tokens because of rotation.
    --
    session_id UUID NOT NULL,


    -- Rotation chain identifier.
    --
    -- All rotated tokens share the same family.
    --
    -- Used for replay detection.
    --
    family_id UUID NOT NULL,


    -- Previous token in rotation chain.
    --
    -- NULL means this is the first token.
    --
    parent_token_id UUID,


    -- SHA256 hash of the refresh token.
    --
    -- The actual token exists only on client side.
    --
    token_hash VARCHAR(255) NOT NULL UNIQUE,


    -- Maximum lifetime of this token.
    --
    expires_at TIMESTAMPTZ NOT NULL,


    -- Timestamp when this token was exchanged.
    --
    -- A consumed token cannot be used again.
    --
    consumed_at TIMESTAMPTZ,


    -- Timestamp when token was revoked.
    --
    revoked_at TIMESTAMPTZ,


    -- Reason why token was revoked.
    --
    revoked_reason refresh_token_revoke_reason,


    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),


    CONSTRAINT fk_refresh_tokens_session

        FOREIGN KEY(session_id)

        REFERENCES sessions(id)

        ON DELETE CASCADE,


    CONSTRAINT fk_refresh_tokens_parent

        FOREIGN KEY(parent_token_id)

        REFERENCES refresh_tokens(id)

        ON DELETE SET NULL,


    CONSTRAINT refresh_token_expiration_check

        CHECK (
            expires_at > created_at
        ),


    CONSTRAINT refresh_token_parent_not_self

        CHECK (
            parent_token_id IS NULL
            OR parent_token_id <> id
        )

);



-- Find tokens belonging to a session.
CREATE INDEX idx_refresh_tokens_session_id

ON refresh_tokens(session_id);



-- Lookup during refresh flow.
--
-- Raw token is hashed first.
--
CREATE INDEX idx_refresh_tokens_hash

ON refresh_tokens(token_hash);



-- Active tokens only.
--
-- Helps:
-- - logout
-- - session management
--
CREATE INDEX idx_refresh_tokens_active

ON refresh_tokens(session_id)

WHERE revoked_at IS NULL;



-- Replay detection.
--
-- Find all tokens from compromised family.
--
CREATE INDEX idx_refresh_tokens_family_id

ON refresh_tokens(family_id);
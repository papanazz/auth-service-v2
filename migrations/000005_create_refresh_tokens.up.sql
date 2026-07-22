-- =====================================================
-- Table: refresh_tokens
--
-- Definition:
-- Stores refresh token lifecycle information.
--
-- Security:
-- Raw refresh tokens are never stored.
-- Only hashes are persisted.
--
-- Supports:
-- - Rotation
-- - Revocation
-- - Replay detection
--
-- =====================================================


CREATE TABLE refresh_tokens (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    session_id UUID NOT NULL,


    token_hash VARCHAR(255) NOT NULL UNIQUE,


    expires_at TIMESTAMP NOT NULL,


    used_at TIMESTAMP,


    revoked_at TIMESTAMP,


    created_at TIMESTAMP NOT NULL
        DEFAULT NOW(),



    CONSTRAINT fk_refresh_tokens_session
        FOREIGN KEY(session_id)
        REFERENCES sessions(id)
        ON DELETE CASCADE,



    CONSTRAINT refresh_token_expiration_check
        CHECK (
            expires_at > created_at
        )

);



CREATE INDEX idx_refresh_tokens_session_id
ON refresh_tokens(session_id);



CREATE INDEX idx_refresh_tokens_active
ON refresh_tokens(session_id)
WHERE revoked_at IS NULL;
-- =====================================================
-- Table: email_verification_tokens
--
-- Definition:
-- Single-use tokens proving control of the email address on a user
-- account.
--
-- Unlike refresh_tokens, there is no family/rotation/replay-detection
-- concept here: a verification token authorizes exactly one thing
-- (marking an email verified), consumed once, and multiple
-- simultaneously-valid tokens for the same user are harmless — they all
-- just confirm the same mailbox. That is what keeps this table so much
-- simpler than refresh_tokens.
--
-- Raw tokens are never stored, same rule as refresh_tokens.
-- =====================================================


CREATE TABLE email_verification_tokens (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    -- Account this token proves an email for.
    user_id UUID NOT NULL,


    -- SHA256 hash of the token. The raw value exists only in the
    -- verification email and, until it expires, a short-lived Redis
    -- cache used to support resending the identical link — never here.
    token_hash VARCHAR(255) NOT NULL UNIQUE,


    -- Maximum lifetime of this token.
    expires_at TIMESTAMPTZ NOT NULL,


    -- Timestamp when this token was exchanged for a verified email.
    -- A consumed token cannot be used again.
    consumed_at TIMESTAMPTZ,


    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),


    CONSTRAINT fk_email_verification_tokens_user

        FOREIGN KEY(user_id)

        REFERENCES users(id)

        ON DELETE CASCADE,


    CONSTRAINT email_verification_token_expiration_check

        CHECK (
            expires_at > created_at
        )

);



-- Find the currently-active token for a user, so a resend can decide
-- whether to reuse it instead of minting a new one.
CREATE INDEX idx_email_verification_tokens_user_id

ON email_verification_tokens(user_id)

WHERE consumed_at IS NULL;



-- Lookup during the verify flow. Raw token is hashed first.
CREATE INDEX idx_email_verification_tokens_hash

ON email_verification_tokens(token_hash);

-- =====================================================
-- Table: authentication_events
--
-- Definition:
-- Immutable authentication activity stream.
--
-- Use Cases:
-- - Security auditing
-- - Brute-force detection
-- - Account investigation
-- - Authentication analytics
--
-- Examples:
--
-- LOGIN_SUCCESS
-- LOGIN_FAILED
-- LOGOUT
-- TOKEN_REFRESHED
-- SESSION_REVOKED
--
-- =====================================================


CREATE TABLE authentication_events (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    event_type VARCHAR(100) NOT NULL
        CHECK (
            length(event_type) > 0
        ),

    user_id UUID,

    -- Used when authentication fails before
    -- user identification.
    email VARCHAR(255),

    ip_address VARCHAR(255),

    user_agent VARCHAR(255),

    success BOOLEAN NOT NULL,

    failure_reason VARCHAR(100),

    metadata JSONB,

    created_at TIMESTAMP NOT NULL
        DEFAULT NOW()

);

CREATE INDEX idx_auth_events_user_created
ON authentication_events(user_id, created_at DESC);

CREATE INDEX idx_auth_events_email_created
ON authentication_events(email, created_at DESC);

CREATE INDEX idx_auth_events_failed_email
ON authentication_events(email, created_at DESC)
WHERE success = FALSE;

CREATE INDEX idx_auth_events_ip_created
ON authentication_events(ip_address, created_at DESC);
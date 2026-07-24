-- =====================================================
-- Table: authentication_events
--
-- Definition:
-- Immutable audit trail for authentication activities.
--
-- Purpose:
-- - Security monitoring
-- - Fraud detection
-- - Incident investigation
-- - Compliance reporting
--
-- Note:
-- This table is append-only.
-- Events should never be updated or deleted.
--
-- Examples:
--
-- LOGIN_SUCCESS
-- LOGIN_FAILED
-- LOGOUT
-- REFRESH_TOKEN_ROTATED
-- REFRESH_TOKEN_REPLAY_DETECTED
--
-- =====================================================


CREATE TABLE authentication_events (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    -- Event name.
    --
    -- Example:
    -- LOGIN_SUCCESS
    -- LOGIN_FAILED
    --
    type VARCHAR(100) NOT NULL,


    -- User identity.
    --
    -- Nullable because failed authentication
    -- may happen before user resolution.
    --
    user_id UUID,


    -- Input identifier.
    --
    -- Example:
    -- email used during login
    --
    email VARCHAR(255),


    -- Client network information.
    --
    ip_address INET,


    -- Client information.
    --
    -- Browser/app information.
    --
    user_agent TEXT,


    -- Authentication result.
    --
    success BOOLEAN NOT NULL,


    -- Failure explanation.
    --
    -- Example:
    -- INVALID_PASSWORD
    -- USER_NOT_FOUND
    --
    reason VARCHAR(255),


    -- Additional event data.
    --
    -- Example:
    --
    -- {
    --    "device_id": "...",
    --    "token_family": "..."
    -- }
    --
    metadata JSONB,


    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()

);



CREATE INDEX idx_auth_events_user_id

ON authentication_events(user_id);



CREATE INDEX idx_auth_events_type

ON authentication_events(type);



CREATE INDEX idx_auth_events_created_at

ON authentication_events(created_at);



CREATE INDEX idx_auth_events_email

ON authentication_events(email);
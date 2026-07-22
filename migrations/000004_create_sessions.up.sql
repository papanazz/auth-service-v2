-- =====================================================
-- Table: sessions
--
-- Definition:
-- Represents an authenticated client session.
--
-- Example:
--
-- User
--  |
--  +-- MacBook Chrome
--  |
--  +-- iPhone App
--
-- Responsibilities:
-- - Device tracking
-- - Session lifecycle
-- - Device-specific logout
--
-- =====================================================


CREATE TABLE sessions (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    user_id UUID NOT NULL,


    -- Client-generated identifier.
    -- Not a hardware identifier.
    device_id VARCHAR(255) NOT NULL,


    device_name VARCHAR(255),


    device_type device_type NOT NULL
        DEFAULT 'WEB',


    user_agent VARCHAR(255),


    ip_address VARCHAR(255),


    last_used_at TIMESTAMP,


    revoked_at TIMESTAMP,


    created_at TIMESTAMP NOT NULL
        DEFAULT NOW(),


    updated_at TIMESTAMP NOT NULL
        DEFAULT NOW(),



    CONSTRAINT fk_sessions_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,



    CONSTRAINT session_expiration_check
        CHECK (
            revoked_at > created_at
        )

);



CREATE INDEX idx_sessions_user_id
ON sessions(user_id);



CREATE INDEX idx_sessions_device_id
ON sessions(device_id);



CREATE INDEX idx_sessions_active
ON sessions(user_id)
WHERE revoked_at IS NULL;
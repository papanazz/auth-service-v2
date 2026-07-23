-- =====================================================
-- Table: sessions
--
-- Definition:
-- Represents an authenticated client session.
--
-- A session represents a user's authenticated presence
-- from a specific client/device.
--
--
-- Example:
--
-- User
--  |
--  |
--  +-- MacBook Chrome Session
--  |       |
--  |       +-- Refresh Token Family
--  |
--  |
--  +-- iPhone App Session
--          |
--          +-- Refresh Token Family
--
--
-- Responsibilities:
--
-- - Device tracking
-- - Session lifecycle management
-- - Device-specific logout
-- - Session expiration
-- - Security monitoring
-- - Refresh token ownership boundary
--
-- =====================================================


CREATE TABLE sessions (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),



    -- Owner of this session.
    --
    -- A user can have multiple sessions:
    --
    -- User A
    --   |
    --   +-- Laptop
    --   |
    --   +-- Mobile Phone
    --
    user_id UUID NOT NULL,



    -- Client-generated identifier.
    --
    -- IMPORTANT:
    -- This is NOT a hardware identifier.
    --
    -- Do NOT store:
    -- - IMEI
    -- - MAC Address
    -- - Hardware fingerprint
    --
    -- Example:
    --
    -- Browser installation UUID
    -- Mobile app installation UUID
    --
    device_id VARCHAR(255) NOT NULL,



    -- Human-readable device name.
    --
    -- Examples:
    --
    -- "Bayu's MacBook Pro"
    -- "iPhone 15"
    -- "Chrome Browser"
    --
    device_name VARCHAR(255),



    -- Type of client.
    --
    -- Examples:
    --
    -- WEB
    -- IOS
    -- ANDROID
    -- DESKTOP
    -- API
    --
    device_type device_type NOT NULL
        DEFAULT 'WEB',



    -- Client user agent information.
    --
    -- Stored for:
    -- - security investigation
    -- - suspicious activity detection
    --
    user_agent TEXT,



    -- Client IP address.
    --
    -- PostgreSQL INET supports:
    -- - IPv4
    -- - IPv6
    --
    ip_address INET,



    -- Last authenticated activity.
    --
    -- Updated when:
    -- - API request authenticated successfully
    --
    last_used_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),



    -- Last refresh token exchange.
    --
    -- Separate from last_used_at because:
    --
    -- A client may continuously refresh tokens
    -- without performing business operations.
    --
    -- Useful for:
    -- - session monitoring
    -- - suspicious refresh detection
    --
    last_refreshed_at TIMESTAMPTZ,



    -- Session expiration time.
    --
    -- Example:
    --
    -- Web:
    --   30 days
    --
    -- Mobile:
    --   90 days
    --
    expires_at TIMESTAMPTZ NOT NULL,



    -- Soft revoke timestamp.
    --
    -- NULL:
    -- session active
    --
    -- NOT NULL:
    -- session terminated
    --
    revoked_at TIMESTAMPTZ,



    -- Reason why session was revoked.
    --
    -- Examples:
    --
    -- USER_LOGOUT
    -- PASSWORD_CHANGED
    -- ADMIN_ACTION
    -- TOKEN_REUSE_DETECTED
    -- SECURITY_POLICY
    --
    revoked_reason VARCHAR(50),



    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),



    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),



    CONSTRAINT fk_sessions_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE RESTRICT,



    -- Session must expire after creation.
    --
    CONSTRAINT sessions_expiration_check
        CHECK (
            expires_at > created_at
        ),



    -- Revocation cannot happen before creation.
    --
    CONSTRAINT sessions_revocation_check
        CHECK (
            revoked_at IS NULL
            OR revoked_at >= created_at
        )

);



-- =====================================================
-- Indexes
-- =====================================================


-- Retrieve all sessions owned by a user.
--
-- Used by:
-- - Security settings page
-- - Device management
--
CREATE INDEX idx_sessions_user_id
ON sessions(user_id);



-- Retrieve active sessions only.
--
-- Used by:
-- - List active devices
-- - Logout all devices
--
CREATE INDEX idx_sessions_active
ON sessions(user_id)
WHERE revoked_at IS NULL;



-- Prevent duplicate active sessions
-- from the same device.
--
-- Historical revoked sessions are allowed.
--
-- Example:
--
-- Allowed:
--
-- iPhone session
-- revoked
--
-- New iPhone session
-- active
--
--
-- Not allowed:
--
-- iPhone session A
-- active
--
-- iPhone session B
-- active
--
CREATE UNIQUE INDEX uq_sessions_active_device
ON sessions(user_id, device_id)
WHERE revoked_at IS NULL;



-- Used by session cleanup worker.
--
-- Example:
--
-- Find expired sessions:
--
-- WHERE expires_at < NOW()
--
CREATE INDEX idx_sessions_expiration
ON sessions(expires_at)
WHERE revoked_at IS NULL;



-- Used for security investigation.
--
-- Example:
--
-- "Show recently active sessions"
--
CREATE INDEX idx_sessions_last_used_at
ON sessions(last_used_at DESC);



-- Used for monitoring refresh activity.
--
-- Example:
--
-- "Find sessions refreshing frequently"
--
CREATE INDEX idx_sessions_last_refreshed_at
ON sessions(last_refreshed_at DESC);
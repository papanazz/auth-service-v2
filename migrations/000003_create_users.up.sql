-- =====================================================
-- Table: users
--
-- Definition:
-- Stores the primary identity entity.
--
-- Responsibilities:
-- - User identity
-- - Credential storage reference
-- - Account lifecycle
-- - Verification status
--
-- Passwords are never stored directly.
--
-- =====================================================


CREATE TABLE users (

    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),


    email VARCHAR(255) NOT NULL UNIQUE,


    password_hash TEXT NOT NULL,


    status user_status NOT NULL
        DEFAULT 'PENDING_VERIFICATION',


    email_verified_at TIMESTAMP,


    last_login_at TIMESTAMP,


    created_at TIMESTAMP NOT NULL
        DEFAULT NOW(),


    updated_at TIMESTAMP NOT NULL
        DEFAULT NOW()

);



CREATE INDEX idx_users_email
ON users(email);
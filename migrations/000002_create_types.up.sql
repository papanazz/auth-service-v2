-- =====================================================
-- Migration: Create Database Types
--
-- Stable domain values only.
--
-- Frequently changing values such as authentication
-- events are intentionally stored as VARCHAR.
--
-- =====================================================


CREATE TYPE user_status AS ENUM (

    'ACTIVE',

    'LOCKED',

    'DISABLED',

    'PENDING_VERIFICATION'

);



CREATE TYPE device_type AS ENUM (

    'WEB',

    'IOS',

    'ANDROID',

    'DESKTOP',

    'SERVICE'

);

CREATE TYPE refresh_token_revoke_reason AS ENUM (

    'LOGOUT',

    'REPLAY_DETECTED',

    'SECURITY_POLICY',

    'EXPIRED'

);
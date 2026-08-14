DROP INDEX IF EXISTS idx_auth_events_session_id;

ALTER TABLE authentication_events

DROP COLUMN IF EXISTS session_id;

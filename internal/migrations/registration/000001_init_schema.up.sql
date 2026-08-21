CREATE TABLE registrations (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    target_ip TEXT NOT NULL,
    api_username TEXT NOT NULL UNIQUE,
    api_key_digest BLOB NOT NULL CHECK (typeof(api_key_digest) = 'blob' AND length(api_key_digest) = 32),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    disabled_at INTEGER,
    challenge_count INTEGER NOT NULL DEFAULT 0 CHECK (challenge_count >= 0),
    challenge_updated_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK ((status = 'active' AND disabled_at IS NULL) OR (status = 'disabled' AND disabled_at IS NOT NULL)),
    CHECK ((challenge_count = 0 AND challenge_updated_at IS NULL) OR (challenge_count > 0 AND challenge_updated_at IS NOT NULL))
);

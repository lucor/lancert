CREATE TABLE sslmate_issuances (
    tbs_sha256 TEXT PRIMARY KEY,
    issuer_name TEXT NOT NULL,
    issuer_caa_domains TEXT NOT NULL,
    dns_names TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    revoked INTEGER,
    first_seen_at INTEGER NOT NULL,
    revocation_time INTEGER,
    revocation_checked_at INTEGER
);

CREATE INDEX sslmate_issuances_not_before ON sslmate_issuances(not_before);

CREATE TABLE sslmate_registration_issuances (
    tbs_sha256 TEXT NOT NULL REFERENCES sslmate_issuances(tbs_sha256) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    PRIMARY KEY(tbs_sha256, hostname)
);

CREATE INDEX sslmate_registration_issuances_hostname ON sslmate_registration_issuances(hostname);

CREATE TABLE sslmate_monitor_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    after_id TEXT NOT NULL DEFAULT '',
    bootstrap_complete INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap_complete IN (0, 1)),
    cutoff_at INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL DEFAULT 0,
    last_success_at INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    refresh_after_id TEXT NOT NULL DEFAULT '',
    refresh_in_progress INTEGER NOT NULL DEFAULT 0 CHECK (refresh_in_progress IN (0, 1)),
    revocation_refreshed_at INTEGER NOT NULL DEFAULT 0
);

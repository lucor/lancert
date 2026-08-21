CREATE TABLE dns_hourly (
    hour TEXT PRIMARY KEY,
    queries INTEGER NOT NULL,
    write_attempts INTEGER NOT NULL,
    write_successes INTEGER NOT NULL,
    latency_count INTEGER NOT NULL,
    latency_sum_us INTEGER NOT NULL,
    latency_max_us INTEGER NOT NULL,
    h0 INTEGER NOT NULL,
    h1 INTEGER NOT NULL,
    h2 INTEGER NOT NULL,
    h3 INTEGER NOT NULL,
    h4 INTEGER NOT NULL,
    h5 INTEGER NOT NULL,
    h6 INTEGER NOT NULL,
    h7 INTEGER NOT NULL,
    h8 INTEGER NOT NULL,
    h9 INTEGER NOT NULL,
    h10 INTEGER NOT NULL,
    h11 INTEGER NOT NULL
);

CREATE TABLE registration_activity_daily (
    date TEXT NOT NULL,
    registration_id TEXT NOT NULL,
    dns_queries INTEGER NOT NULL,
    challenge_updates INTEGER NOT NULL,
    PRIMARY KEY (date, registration_id)
);

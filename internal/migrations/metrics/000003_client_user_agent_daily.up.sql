CREATE TABLE client_user_agent_daily (
    date TEXT NOT NULL,
    client_family TEXT NOT NULL CHECK (client_family IN ('lancert-cli','acme.sh','cert-manager','caddy','lego','traefik','certbot','curl','other','unknown')),
    user_agent TEXT NOT NULL CHECK (length(CAST(user_agent AS BLOB)) <= 512),
    accepted_updates INTEGER NOT NULL CHECK (accepted_updates >= 0),
    PRIMARY KEY (date, client_family, user_agent)
);

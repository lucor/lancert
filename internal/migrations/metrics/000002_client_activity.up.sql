CREATE TABLE client_activity_daily (
    date TEXT NOT NULL,
    client_family TEXT NOT NULL CHECK (client_family IN ('lancert-cli','acme.sh','cert-manager','caddy','lego','traefik','certbot','curl','other','unknown')),
    accepted_updates INTEGER NOT NULL,
    PRIMARY KEY (date, client_family)
);

CREATE TABLE IF NOT EXISTS rustaccio_quota_usage (
    day TEXT NOT NULL,
    tenant_key TEXT NOT NULL,
    metric TEXT NOT NULL,
    used BIGINT NOT NULL CHECK (used >= 0),
    PRIMARY KEY (day, tenant_key, metric)
);

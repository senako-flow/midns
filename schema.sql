CREATE TABLE zones (
    id         BIGINT PRIMARY KEY,

    name       VARCHAR(253) NOT NULL UNIQUE CHECK (name = lower(name)),

    serial     BIGINT NOT NULL DEFAULT 1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE records (
    id         BIGINT PRIMARY KEY,
    zone_id    BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,

    ttl        INT NOT NULL DEFAULT 300,
    name       VARCHAR(253) NOT NULL CHECK (name = lower(name)),
    record     INT NOT NULL,

    raw_data   BYTEA NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_records_zone   ON records (zone_id);
CREATE INDEX idx_records_lookup ON records (name, record);

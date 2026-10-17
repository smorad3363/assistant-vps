PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO metadata(key, value) VALUES ('schema_version', '1');

CREATE TABLE IF NOT EXISTS forward_history (
    forward_id INTEGER NOT NULL CHECK(forward_id BETWEEN 1 AND 4095),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    tunnel_id INTEGER NOT NULL CHECK(tunnel_id BETWEEN 1 AND 4095),
    valid_from_ms INTEGER NOT NULL,
    valid_to_ms INTEGER,
    mapping_json TEXT NOT NULL,
    PRIMARY KEY (forward_id, generation)
);

CREATE TABLE IF NOT EXISTS samples (
    forward_id INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    tunnel_id INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL CHECK(end_ms > start_ms),
    upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
    download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
    PRIMARY KEY (forward_id, epoch, start_ms),
    FOREIGN KEY (forward_id, generation)
        REFERENCES forward_history(forward_id, generation)
);
CREATE INDEX IF NOT EXISTS samples_window ON samples(forward_id, end_ms);
CREATE INDEX IF NOT EXISTS samples_tunnel_window ON samples(tunnel_id, end_ms);
CREATE INDEX IF NOT EXISTS samples_retention ON samples(end_ms);

CREATE TABLE IF NOT EXISTS baselines (
    forward_id INTEGER PRIMARY KEY,
    generation INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    observed_ms INTEGER NOT NULL,
    monotonic_ns INTEGER NOT NULL,
    upload_counter INTEGER NOT NULL CHECK(upload_counter >= 0),
    download_counter INTEGER NOT NULL CHECK(download_counter >= 0)
);

CREATE TABLE IF NOT EXISTS gaps (
    forward_id INTEGER NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL CHECK(end_ms >= start_ms),
    reason TEXT NOT NULL,
    PRIMARY KEY (forward_id, start_ms)
);

CREATE TABLE IF NOT EXISTS interface_samples (
    tunnel_id INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL CHECK(end_ms > start_ms),
    rx_bytes INTEGER NOT NULL CHECK(rx_bytes >= 0),
    tx_bytes INTEGER NOT NULL CHECK(tx_bytes >= 0),
    PRIMARY KEY (tunnel_id, epoch, start_ms)
);

CREATE TABLE IF NOT EXISTS tombstones (
    kind TEXT NOT NULL CHECK(kind IN ('tunnel', 'forward')),
    object_id INTEGER NOT NULL,
    deleted_ms INTEGER NOT NULL,
    PRIMARY KEY (kind, object_id)
);

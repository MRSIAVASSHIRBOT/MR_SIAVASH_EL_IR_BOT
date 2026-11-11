CREATE TABLE IF NOT EXISTS telegram_sessions (
    client_id TEXT PRIMARY KEY,
    telegram_user_id INTEGER NOT NULL,
    credential_ciphertext TEXT NOT NULL,
    access_expires_at INTEGER NOT NULL,
    scopes_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS telegram_processed_updates (
    update_id INTEGER PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('processing', 'retry', 'done')),
    lease_until INTEGER NOT NULL,
    processed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_telegram_processed_updates_processed_at
    ON telegram_processed_updates (processed_at);

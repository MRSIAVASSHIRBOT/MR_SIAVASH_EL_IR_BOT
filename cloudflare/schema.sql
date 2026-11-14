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

CREATE TABLE IF NOT EXISTS telegram_jobs (
    job_id TEXT PRIMARY KEY,
    update_id INTEGER NOT NULL UNIQUE,
    chat_id INTEGER NOT NULL,
    telegram_user_id INTEGER NOT NULL,
    payload_ciphertext TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'sending', 'done')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    lease_token_hash TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telegram_jobs_pending
    ON telegram_jobs (state, lease_until, created_at);

CREATE INDEX IF NOT EXISTS idx_telegram_jobs_updated_at
    ON telegram_jobs (updated_at);

CREATE TABLE IF NOT EXISTS bridge_nonces (
    nonce_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bridge_nonces_expires_at
    ON bridge_nonces (expires_at);

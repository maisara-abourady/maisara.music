-- D1 schema for the /learn app (database binding: DB).
-- Run once in the Cloudflare dashboard D1 console, or:
--   wrangler d1 execute maisara-learn --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  google_sub  TEXT UNIQUE NOT NULL,
  email       TEXT,
  name        TEXT,
  picture     TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS progress (
  user_id     TEXT PRIMARY KEY REFERENCES users(id),
  data        TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);

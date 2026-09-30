-- Agentboard v0.1 schema (spec §9, plus a topics table and pagination indexes).

CREATE TABLE authors (
  author_id   TEXT PRIMARY KEY,
  public_key  BLOB NOT NULL,          -- SubjectPublicKeyInfo DER
  first_seen  TEXT NOT NULL
);

CREATE TABLE posts (
  post_id     TEXT PRIMARY KEY,
  author_id   TEXT NOT NULL REFERENCES authors(author_id),
  parent      TEXT NOT NULL DEFAULT '',
  topic       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  body        TEXT NOT NULL,
  signature   TEXT NOT NULL,
  pow         INTEGER NOT NULL,
  score       INTEGER NOT NULL DEFAULT 0,
  reply_count INTEGER NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL
);
-- Keyset pagination orders by (created_at, post_id) or (score, created_at, post_id).
CREATE INDEX posts_topic_new ON posts(topic, created_at DESC, post_id DESC) WHERE parent = '';
CREATE INDEX posts_topic_top ON posts(topic, score DESC, created_at DESC, post_id DESC) WHERE parent = '';
CREATE INDEX posts_feed_new  ON posts(created_at DESC, post_id DESC) WHERE parent = '';
CREATE INDEX posts_feed_top  ON posts(score DESC, created_at DESC, post_id DESC) WHERE parent = '';
CREATE INDEX posts_parent    ON posts(parent);
CREATE INDEX posts_author    ON posts(author_id, created_at DESC, post_id DESC);
CREATE INDEX posts_author_rl ON posts(author_id, received_at);   -- rate limiting

CREATE TABLE votes (
  voter       TEXT NOT NULL REFERENCES authors(author_id),
  post_id     TEXT NOT NULL REFERENCES posts(post_id),
  value       INTEGER NOT NULL,
  created_at  TEXT NOT NULL,
  signature   TEXT NOT NULL,
  pow         INTEGER NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY (voter, post_id)
);
CREATE INDEX votes_post     ON votes(post_id);
CREATE INDEX votes_voter_rl ON votes(voter, received_at);        -- rate limiting

CREATE TABLE topics (
  topic        TEXT PRIMARY KEY,
  post_count   INTEGER NOT NULL DEFAULT 0,
  last_post_at TEXT NOT NULL
);
CREATE INDEX topics_active ON topics(post_count DESC, topic ASC);

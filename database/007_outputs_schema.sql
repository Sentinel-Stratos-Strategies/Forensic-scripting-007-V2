PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  schema_name TEXT NOT NULL,
  version INTEGER NOT NULL,
  applied_at_utc TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT,
  PRIMARY KEY (schema_name, version)
);

INSERT OR IGNORE INTO schema_migrations(schema_name, version, description)
VALUES('007_outputs', 1, 'Initial 007 output schema');

CREATE TABLE IF NOT EXISTS dashboard_cards (
  card_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  title TEXT NOT NULL,
  value TEXT,
  severity TEXT,
  source_query TEXT,
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_rows (
  row_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  event_time TEXT,
  event_time_utc TEXT,
  lane TEXT,
  title TEXT NOT NULL,
  summary TEXT,
  source_ref TEXT,
  confidence TEXT
);

CREATE TABLE IF NOT EXISTS report_sections (
  section_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  report_name TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  title TEXT NOT NULL,
  body_markdown TEXT NOT NULL,
  source_refs_json TEXT
);

CREATE TABLE IF NOT EXISTS export_manifests (
  export_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  export_path TEXT NOT NULL,
  export_type TEXT NOT NULL,
  sha256 TEXT,
  created_at_utc TEXT NOT NULL
);

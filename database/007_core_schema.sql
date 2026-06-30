PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  schema_name TEXT NOT NULL,
  version INTEGER NOT NULL,
  applied_at_utc TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT,
  PRIMARY KEY (schema_name, version)
);

INSERT OR IGNORE INTO schema_migrations(schema_name, version, description)
VALUES('007_core', 1, 'Initial 007 core evidence schema');

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  title TEXT,
  created_at_utc TEXT NOT NULL,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  started_at_utc TEXT NOT NULL,
  completed_at_utc TEXT,
  tool TEXT NOT NULL,
  source_root TEXT,
  output_dir TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  source TEXT NOT NULL,
  name TEXT,
  model TEXT,
  os_name TEXT,
  os_version TEXT,
  serial_or_udid_redacted TEXT,
  first_seen_utc TEXT
);

CREATE TABLE IF NOT EXISTS apps (
  app_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  bundle_id TEXT,
  display_name TEXT,
  path TEXT,
  source_lane TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  run_id TEXT REFERENCES runs(run_id),
  source_lane TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  path TEXT NOT NULL,
  rel_path TEXT,
  size INTEGER,
  created_at TEXT,
  modified_at TEXT,
  changed_at TEXT,
  accessed_at TEXT,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS hashes (
  hash_id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
  algorithm TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE(artifact_id, algorithm, value)
);

CREATE TABLE IF NOT EXISTS tcc_rows (
  tcc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  run_id TEXT REFERENCES runs(run_id),
  scope TEXT NOT NULL,
  service TEXT,
  client TEXT,
  client_type TEXT,
  auth_value TEXT,
  auth_reason TEXT,
  auth_version TEXT,
  last_modified TEXT,
  source_db TEXT
);

CREATE TABLE IF NOT EXISTS pcap_flows (
  flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  run_id TEXT REFERENCES runs(run_id),
  start_time_utc TEXT,
  end_time_utc TEXT,
  src TEXT,
  dst TEXT,
  proto TEXT,
  sni_or_host TEXT,
  bytes INTEGER,
  packets INTEGER,
  source_file TEXT
);

CREATE TABLE IF NOT EXISTS process_samples (
  sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  run_id TEXT REFERENCES runs(run_id),
  sample_time_utc TEXT NOT NULL,
  app_key TEXT,
  pid INTEGER,
  ppid INTEGER,
  command TEXT,
  executable TEXT
);

CREATE TABLE IF NOT EXISTS app_bundles (
  bundle_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  app_id TEXT REFERENCES apps(app_id),
  artifact_id TEXT REFERENCES artifacts(artifact_id),
  kind TEXT,
  team_id TEXT,
  codesign_identifier TEXT,
  codesign_timestamp TEXT,
  spctl_result TEXT,
  info_plist TEXT,
  entitlements_json TEXT
);

CREATE TABLE IF NOT EXISTS mobile_artifacts (
  mobile_artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  device_id TEXT REFERENCES devices(device_id),
  source_report TEXT NOT NULL,
  root_selection TEXT,
  path TEXT,
  is_directory INTEGER,
  size INTEGER,
  created_at TEXT,
  modified_at TEXT,
  type_identifier TEXT,
  sha256 TEXT
);

CREATE TABLE IF NOT EXISTS claims (
  claim_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  title TEXT NOT NULL,
  support_level TEXT NOT NULL,
  status TEXT NOT NULL,
  explanation TEXT
);

CREATE TABLE IF NOT EXISTS claim_evidence (
  claim_id TEXT NOT NULL REFERENCES claims(claim_id),
  artifact_id TEXT REFERENCES artifacts(artifact_id),
  source_table TEXT,
  source_pk TEXT,
  evidence_role TEXT,
  note TEXT,
  PRIMARY KEY (claim_id, source_table, source_pk)
);

CREATE TABLE IF NOT EXISTS excluded_claims (
  excluded_claim_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  claim_text TEXT NOT NULL,
  exclusion_reason TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
  custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  event_time_utc TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT
);

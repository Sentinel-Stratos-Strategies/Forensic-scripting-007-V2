PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  schema_name TEXT NOT NULL,
  version INTEGER NOT NULL,
  applied_at_utc TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT,
  PRIMARY KEY (schema_name, version)
);

INSERT OR IGNORE INTO schema_migrations(schema_name, version, description)
VALUES('007_graph', 1, 'Initial 007 graph schema');

CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  node_type TEXT NOT NULL,
  label TEXT NOT NULL,
  source_table TEXT,
  source_pk TEXT,
  attrs_json TEXT
);

CREATE TABLE IF NOT EXISTS edges (
  edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_node TEXT NOT NULL REFERENCES nodes(node_id),
  to_node TEXT NOT NULL REFERENCES nodes(node_id),
  edge_type TEXT NOT NULL,
  confidence TEXT,
  source_table TEXT,
  source_pk TEXT,
  attrs_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_node);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type);

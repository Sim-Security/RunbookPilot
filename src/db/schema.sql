-- RunbookPilot Database Schema v1
-- SQLite with WAL mode for concurrent read access

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);

-- Runbook definitions (cached from YAML files)
CREATE TABLE IF NOT EXISTS runbooks (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  automation_level TEXT NOT NULL CHECK(automation_level IN ('L0', 'L1', 'L2')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  loaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(id, version)
);

CREATE INDEX IF NOT EXISTS idx_runbooks_name ON runbooks(name);
CREATE INDEX IF NOT EXISTS idx_runbooks_level ON runbooks(automation_level);

-- Execution history
CREATE TABLE IF NOT EXISTS executions (
  execution_id TEXT PRIMARY KEY,
  runbook_id TEXT NOT NULL,
  runbook_version TEXT NOT NULL,
  runbook_name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN (
    'idle', 'validating', 'planning', 'awaiting_approval',
    'executing', 'rolling_back', 'completed', 'failed', 'cancelled'
  )),
  mode TEXT NOT NULL CHECK(mode IN ('production', 'simulation', 'dry-run')),
  context_snapshot TEXT,
  error TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_executions_runbook ON executions(runbook_id);
CREATE INDEX IF NOT EXISTS idx_executions_state ON executions(state);
CREATE INDEX IF NOT EXISTS idx_executions_started ON executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_executions_mode ON executions(mode);

-- Step execution results
CREATE TABLE IF NOT EXISTS step_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  step_name TEXT NOT NULL,
  action TEXT NOT NULL,
  success INTEGER NOT NULL,
  output TEXT,
  error TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_step_results_execution ON step_results(execution_id);
CREATE INDEX IF NOT EXISTS idx_step_results_action ON step_results(action);
CREATE INDEX IF NOT EXISTS idx_step_results_success ON step_results(success);

-- Approval queue (L2 actions pending approval)
CREATE TABLE IF NOT EXISTS approval_queue (
  request_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  runbook_name TEXT NOT NULL,
  step_id TEXT NOT NULL,
  step_name TEXT NOT NULL,
  action TEXT NOT NULL,
  parameters TEXT NOT NULL,
  simulation_result TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'denied', 'expired')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  denial_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_queue(status);
CREATE INDEX IF NOT EXISTS idx_approval_requested ON approval_queue(requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_expires ON approval_queue(expires_at);

-- Audit log (immutable record of all actions)
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  execution_id TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  details TEXT NOT NULL,
  success BOOLEAN NOT NULL,
  prev_hash TEXT,
  hash TEXT NOT NULL,
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_log(execution_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

-- Metrics (aggregated performance data)
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  dimensions TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(period_start, period_end, metric_name, dimensions)
);

CREATE INDEX IF NOT EXISTS idx_metrics_period ON metrics(period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name);

-- Registered adapters
CREATE TABLE IF NOT EXISTS adapters (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config TEXT NOT NULL,
  health_status TEXT CHECK(health_status IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
  last_health_check TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_adapters_enabled ON adapters(enabled);
CREATE INDEX IF NOT EXISTS idx_adapters_type ON adapters(type);

-- DetectForge integration (runbook suggestions by MITRE technique)
CREATE TABLE IF NOT EXISTS detectforge_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mitre_technique TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  confidence TEXT CHECK(confidence IN ('low', 'medium', 'high')),
  source TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_detectforge_technique ON detectforge_mappings(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_detectforge_runbook ON detectforge_mappings(runbook_id);

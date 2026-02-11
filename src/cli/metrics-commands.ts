/**
 * CLI Metrics Dashboard Commands (S5-004)
 *
 * Adds `metrics` subcommands to the RunbookPilot CLI for
 * execution stats, MTTD/MTTR, approval latency, and playbook coverage.
 *
 * @module cli/metrics-commands
 */

import type { Command } from 'commander';
import type Database from 'better-sqlite3';

// ---------------------------------------------------------------------------
// Types (inline — depends on MetricsCollector being available)
// ---------------------------------------------------------------------------

interface TimeRange {
  start: string;
  end: string;
}

interface ApprovalLatencyMetrics {
  avg_latency_ms: number;
  median_latency_ms: number;
  p95_latency_ms: number;
  total_approvals: number;
  by_action: Record<string, number>;
}

interface PlaybookCoverageMetrics {
  total_techniques_mapped: number;
  total_techniques_seen: number;
  coverage_ratio: number;
  unmapped_techniques: string[];
  usage_by_technique: Record<string, number>;
  most_used_playbooks: Array<{ runbook_id: string; runbook_name: string; count: number }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function timeRange(period: '24h' | '7d' | '30d' | 'all'): TimeRange {
  const end = new Date().toISOString();
  let start: string;

  switch (period) {
    case '24h':
      start = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      break;
    case '7d':
      start = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      break;
    case '30d':
      start = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      break;
    case 'all':
      start = '1970-01-01T00:00:00.000Z';
      break;
  }

  return { start, end };
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function formatPercent(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

/**
 * Query execution stats directly from DB for the metrics dashboard.
 */
function getExecutionStats(db: Database.Database, range: TimeRange) {
  const total = (db.prepare(
    'SELECT COUNT(*) as count FROM executions WHERE started_at >= ? AND started_at <= ?',
  ).get(range.start, range.end) as { count: number }).count;

  const successful = (db.prepare(
    "SELECT COUNT(*) as count FROM executions WHERE state = 'completed' AND started_at >= ? AND started_at <= ?",
  ).get(range.start, range.end) as { count: number }).count;

  const failed = (db.prepare(
    "SELECT COUNT(*) as count FROM executions WHERE state = 'failed' AND started_at >= ? AND started_at <= ?",
  ).get(range.start, range.end) as { count: number }).count;

  const cancelled = (db.prepare(
    "SELECT COUNT(*) as count FROM executions WHERE state = 'cancelled' AND started_at >= ? AND started_at <= ?",
  ).get(range.start, range.end) as { count: number }).count;

  const avgDuration = (db.prepare(
    'SELECT AVG(duration_ms) as avg_ms FROM executions WHERE duration_ms IS NOT NULL AND started_at >= ? AND started_at <= ?',
  ).get(range.start, range.end) as { avg_ms: number | null }).avg_ms ?? 0;

  const byLevel = db.prepare(`
    SELECT
      COALESCE(json_extract(context_snapshot, '$.mode'), mode) as exec_mode,
      COUNT(*) as count
    FROM executions
    WHERE started_at >= ? AND started_at <= ?
    GROUP BY exec_mode
  `).all(range.start, range.end) as Array<{ exec_mode: string; count: number }>;

  return { total, successful, failed, cancelled, avgDuration, byLevel };
}

function getApprovalStats(db: Database.Database, range: TimeRange): ApprovalLatencyMetrics {
  const rows = db.prepare(`
    SELECT
      action,
      requested_at,
      approved_at
    FROM approval_queue
    WHERE status = 'approved'
      AND approved_at IS NOT NULL
      AND requested_at >= ? AND requested_at <= ?
  `).all(range.start, range.end) as Array<{ action: string; requested_at: string; approved_at: string }>;

  if (rows.length === 0) {
    return { avg_latency_ms: 0, median_latency_ms: 0, p95_latency_ms: 0, total_approvals: 0, by_action: {} };
  }

  const latencies = rows.map((r) => {
    return new Date(r.approved_at).getTime() - new Date(r.requested_at).getTime();
  }).sort((a, b) => a - b);

  const avg = latencies.reduce((sum, l) => sum + l, 0) / latencies.length;
  const median = latencies[Math.floor(latencies.length / 2)]!;
  const p95 = latencies[Math.ceil(0.95 * latencies.length) - 1] ?? latencies[latencies.length - 1]!;

  const byAction: Record<string, number> = {};
  for (const row of rows) {
    const latency = new Date(row.approved_at).getTime() - new Date(row.requested_at).getTime();
    byAction[row.action] = (byAction[row.action] ?? 0) + latency;
  }
  // Convert sums to averages
  const actionCounts: Record<string, number> = {};
  for (const row of rows) {
    actionCounts[row.action] = (actionCounts[row.action] ?? 0) + 1;
  }
  for (const action of Object.keys(byAction)) {
    byAction[action] = byAction[action]! / (actionCounts[action] ?? 1);
  }

  return { avg_latency_ms: avg, median_latency_ms: median, p95_latency_ms: p95, total_approvals: rows.length, by_action: byAction };
}

function getCoverageStats(db: Database.Database, range: TimeRange): PlaybookCoverageMetrics {
  // Count mapped techniques from config (approximate from DB)
  const techniqueRows = db.prepare(`
    SELECT DISTINCT mitre_technique FROM detectforge_mappings
  `).all() as Array<{ mitre_technique: string }>;

  const mappedTechniques = new Set(techniqueRows.map((r) => r.mitre_technique));

  // Count techniques seen in executions
  const seenRows = db.prepare(`
    SELECT context_snapshot FROM executions
    WHERE context_snapshot IS NOT NULL
      AND started_at >= ? AND started_at <= ?
  `).all(range.start, range.end) as Array<{ context_snapshot: string }>;

  const seenTechniques = new Set<string>();
  const usageByTechnique: Record<string, number> = {};

  for (const row of seenRows) {
    try {
      const ctx = JSON.parse(row.context_snapshot) as Record<string, unknown>;
      const alert = ctx['alert'] as Record<string, unknown> | undefined;
      const threat = alert?.['threat'] as Record<string, unknown> | undefined;
      const technique = threat?.['technique'] as { id?: string[] } | undefined;
      if (technique?.id) {
        for (const id of technique.id) {
          seenTechniques.add(id);
          usageByTechnique[id] = (usageByTechnique[id] ?? 0) + 1;
        }
      }
    } catch {
      // Skip unparseable
    }
  }

  const unmapped = [...seenTechniques].filter((t) => !mappedTechniques.has(t));

  // Top playbooks
  const topPlaybooks = db.prepare(`
    SELECT runbook_id, runbook_name, COUNT(*) as count
    FROM executions
    WHERE started_at >= ? AND started_at <= ?
    GROUP BY runbook_id
    ORDER BY count DESC
    LIMIT 10
  `).all(range.start, range.end) as Array<{ runbook_id: string; runbook_name: string; count: number }>;

  return {
    total_techniques_mapped: mappedTechniques.size,
    total_techniques_seen: seenTechniques.size,
    coverage_ratio: seenTechniques.size > 0 ? mappedTechniques.size / seenTechniques.size : 1,
    unmapped_techniques: unmapped,
    usage_by_technique: usageByTechnique,
    most_used_playbooks: topPlaybooks,
  };
}

// ---------------------------------------------------------------------------
// Register commands
// ---------------------------------------------------------------------------

export function registerMetricsCommands(program: Command): void {
  const metricsCmd = program
    .command('metrics')
    .description('Display execution metrics dashboard');

  metricsCmd
    .command('summary')
    .description('Show execution stats overview')
    .option('-p, --period <period>', 'Time range: 24h, 7d, 30d, all', '7d')
    .option('--json', 'Output as JSON')
    .action(async (options: Record<string, string>) => {
      const { initDatabase } = await import('../db/index.ts');
      const { loadConfig } = await import('../config/index.ts');

      const config = loadConfig();
      const db = initDatabase({ path: config.dbPath });
      const range = timeRange(options['period'] as '24h' | '7d' | '30d' | 'all');

      const stats = getExecutionStats(db, range);

      if (options['json']) {
        console.log(JSON.stringify(stats, null, 2));
        return;
      }

      console.log('');
      console.log(`Execution Metrics (${options['period']})`);
      console.log('='.repeat(50));
      console.log('');
      console.log(`  Total Executions:   ${stats.total}`);
      console.log(`  Successful:         ${stats.successful}`);
      console.log(`  Failed:             ${stats.failed}`);
      console.log(`  Cancelled:          ${stats.cancelled}`);
      console.log(`  Success Rate:       ${stats.total > 0 ? formatPercent(stats.successful / stats.total) : 'N/A'}`);
      console.log(`  Avg Duration:       ${formatMs(stats.avgDuration)}`);
      console.log('');

      if (stats.byLevel.length > 0) {
        console.log('  By Mode:');
        for (const { exec_mode, count } of stats.byLevel) {
          console.log(`    ${exec_mode.padEnd(15)} ${count}`);
        }
        console.log('');
      }
    });

  metricsCmd
    .command('latency')
    .description('Show approval latency metrics')
    .option('-p, --period <period>', 'Time range: 24h, 7d, 30d, all', '7d')
    .option('--json', 'Output as JSON')
    .action(async (options: Record<string, string>) => {
      const { initDatabase } = await import('../db/index.ts');
      const { loadConfig } = await import('../config/index.ts');

      const config = loadConfig();
      const db = initDatabase({ path: config.dbPath });
      const range = timeRange(options['period'] as '24h' | '7d' | '30d' | 'all');

      const latency = getApprovalStats(db, range);

      if (options['json']) {
        console.log(JSON.stringify(latency, null, 2));
        return;
      }

      console.log('');
      console.log(`Approval Latency (${options['period']})`);
      console.log('='.repeat(50));
      console.log('');
      console.log(`  Total Approvals:    ${latency.total_approvals}`);
      console.log(`  Avg Latency:        ${formatMs(latency.avg_latency_ms)}`);
      console.log(`  Median Latency:     ${formatMs(latency.median_latency_ms)}`);
      console.log(`  P95 Latency:        ${formatMs(latency.p95_latency_ms)}`);
      console.log('');

      if (Object.keys(latency.by_action).length > 0) {
        console.log('  By Action:');
        for (const [action, avgMs] of Object.entries(latency.by_action)) {
          console.log(`    ${action.padEnd(20)} ${formatMs(avgMs)}`);
        }
        console.log('');
      }
    });

  metricsCmd
    .command('coverage')
    .description('Show playbook coverage for ATT&CK techniques')
    .option('-p, --period <period>', 'Time range: 24h, 7d, 30d, all', '30d')
    .option('--json', 'Output as JSON')
    .action(async (options: Record<string, string>) => {
      const { initDatabase } = await import('../db/index.ts');
      const { loadConfig } = await import('../config/index.ts');

      const config = loadConfig();
      const db = initDatabase({ path: config.dbPath });
      const range = timeRange(options['period'] as '24h' | '7d' | '30d' | 'all');

      const coverage = getCoverageStats(db, range);

      if (options['json']) {
        console.log(JSON.stringify(coverage, null, 2));
        return;
      }

      console.log('');
      console.log(`Playbook Coverage (${options['period']})`);
      console.log('='.repeat(50));
      console.log('');
      console.log(`  Techniques Mapped:   ${coverage.total_techniques_mapped}`);
      console.log(`  Techniques Seen:     ${coverage.total_techniques_seen}`);
      console.log(`  Coverage Ratio:      ${formatPercent(coverage.coverage_ratio)}`);
      console.log('');

      if (coverage.unmapped_techniques.length > 0) {
        console.log('  Unmapped Techniques (gaps):');
        for (const t of coverage.unmapped_techniques.slice(0, 20)) {
          console.log(`    - ${t}`);
        }
        console.log('');
      }

      if (coverage.most_used_playbooks.length > 0) {
        console.log('  Top Playbooks:');
        console.log('  ' + 'Runbook'.padEnd(40) + 'Executions');
        console.log('  ' + '-'.repeat(52));
        for (const pb of coverage.most_used_playbooks) {
          console.log(`  ${pb.runbook_name.slice(0, 38).padEnd(40)}${pb.count}`);
        }
        console.log('');
      }
    });
}

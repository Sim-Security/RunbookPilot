/**
 * Unified Metrics Collector
 *
 * Combines execution metrics (S5-001), approval latency (S5-002), and
 * playbook coverage (S5-003) into a single collector module. All queries
 * use prepared statements against SQLite via better-sqlite3.
 *
 * Key metrics:
 * - Execution: total/success/fail counts, avg duration, by-level/by-technique breakdowns
 * - MTTD: alert @timestamp -> execution started_at (parsed from context_snapshot JSON)
 * - MTTR: execution started_at -> completed_at
 * - Approval latency: approved_at - requested_at with avg/median/p95
 * - Playbook coverage: technique-playbook-map.yml vs. observed techniques
 *
 * Aggregated snapshots are cached in the `metrics` table.
 *
 * @module metrics/collector
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import YAML from 'yaml';
import type Database from 'better-sqlite3';
import type { AutomationLevel, AdapterHealth, MetricsSnapshot } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Exported Interfaces
// ---------------------------------------------------------------------------

export interface TimeRange {
  start: string; // ISO8601
  end: string;   // ISO8601
}

export interface ApprovalLatencyMetrics {
  avg_latency_ms: number;
  median_latency_ms: number;
  p95_latency_ms: number;
  total_approvals: number;
  by_action: Record<string, number>; // action -> avg latency ms
}

export interface PlaybookCoverageMetrics {
  total_techniques_mapped: number;
  total_techniques_seen: number;
  coverage_ratio: number; // 0-1
  unmapped_techniques: string[];
  usage_by_technique: Record<string, number>; // technique -> execution count
  most_used_playbooks: Array<{ runbook_id: string; runbook_name: string; count: number }>;
}

// ---------------------------------------------------------------------------
// Internal Row Types
// ---------------------------------------------------------------------------

interface ExecutionCountRow {
  readonly state: string;
  readonly count: number;
}

interface AvgDurationRow {
  readonly avg_duration: number | null;
}

interface TopRunbookRow {
  readonly runbook_id: string;
  readonly count: number;
}

interface AdapterHealthRow {
  readonly name: string;
  readonly health_status: string | null;
}

interface ContextSnapshotRow {
  readonly execution_id: string;
  readonly started_at: string;
  readonly context_snapshot: string | null;
}

interface MttrRow {
  readonly started_at: string;
  readonly completed_at: string;
}

interface ApprovalRow {
  readonly request_id: string;
  readonly action: string;
  readonly requested_at: string;
  readonly approved_at: string;
}

interface PlaybookUsageRow {
  readonly runbook_id: string;
  readonly runbook_name: string;
  readonly count: number;
}

// ---------------------------------------------------------------------------
// Technique-Playbook Map Types
// ---------------------------------------------------------------------------

interface TechniqueMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  playbook_files: string[];
  default_level: string;
}

interface TechniquePlaybookMapFile {
  version: string;
  description: string;
  default_playbook: string;
  mappings: TechniqueMapping[];
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

export class MetricsCollector {
  private readonly db: Database.Database;

  // Prepared statements
  private readonly stmtExecutionCounts: Database.Statement;
  private readonly stmtAvgDuration: Database.Statement;
  private readonly stmtTopRunbooks: Database.Statement;
  private readonly stmtAdapterHealth: Database.Statement;
  private readonly stmtContextSnapshots: Database.Statement;
  private readonly stmtMttrRows: Database.Statement;
  private readonly stmtApprovedEntries: Database.Statement;
  private readonly stmtPlaybookUsage: Database.Statement;
  private readonly stmtInsertMetric: Database.Statement;
  private readonly stmtTotalExecutions: Database.Statement;
  private readonly stmtSuccessCount: Database.Statement;

  // Cached technique map (loaded once from YAML)
  private mappedTechniques: Set<string> | null = null;

  constructor(db: Database.Database) {
    this.db = db;

    // -- Execution metrics statements --

    // Count executions by state within a time range
    this.stmtExecutionCounts = db.prepare(`
      SELECT state, COUNT(*) as count
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
      GROUP BY state
    `);

    // Average duration for completed executions
    this.stmtAvgDuration = db.prepare(`
      SELECT AVG(duration_ms) as avg_duration
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
        AND duration_ms IS NOT NULL
    `);

    // Top runbooks by execution count
    this.stmtTopRunbooks = db.prepare(`
      SELECT runbook_id, COUNT(*) as count
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
      GROUP BY runbook_id
      ORDER BY count DESC
      LIMIT 10
    `);

    // Adapter health status from adapters table
    this.stmtAdapterHealth = db.prepare(`
      SELECT name, health_status
      FROM adapters
      WHERE enabled = 1
    `);

    // Context snapshots for MTTD calculation (alert @timestamp -> started_at)
    this.stmtContextSnapshots = db.prepare(`
      SELECT execution_id, started_at, context_snapshot
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
        AND context_snapshot IS NOT NULL
        AND state IN ('completed', 'failed')
    `);

    // MTTR rows: started_at and completed_at for completed executions
    this.stmtMttrRows = db.prepare(`
      SELECT started_at, completed_at
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
        AND completed_at IS NOT NULL
        AND state IN ('completed', 'failed')
    `);

    // Approved entries from approval_queue for latency calculation
    this.stmtApprovedEntries = db.prepare(`
      SELECT request_id, action, requested_at, approved_at
      FROM approval_queue
      WHERE status = 'approved'
        AND approved_at IS NOT NULL
        AND requested_at >= ? AND requested_at <= ?
    `);

    // Playbook usage: runbook_id, runbook_name, count
    this.stmtPlaybookUsage = db.prepare(`
      SELECT runbook_id, runbook_name, COUNT(*) as count
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
      GROUP BY runbook_id, runbook_name
      ORDER BY count DESC
    `);

    // Insert aggregated metric into the metrics table
    this.stmtInsertMetric = db.prepare(`
      INSERT OR REPLACE INTO metrics (period_start, period_end, metric_name, metric_value, dimensions)
      VALUES (?, ?, ?, ?, ?)
    `);

    // Total executions in a time range
    this.stmtTotalExecutions = db.prepare(`
      SELECT COUNT(*) as count
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
    `);

    // Successful execution count
    this.stmtSuccessCount = db.prepare(`
      SELECT COUNT(*) as count
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
        AND state = 'completed'
    `);
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Collect a full MetricsSnapshot for the given time range.
   * This merges execution counts, timing, MTTD/MTTR, level breakdowns,
   * technique breakdowns, top runbooks, and adapter health.
   */
  getExecutionMetrics(range: TimeRange): MetricsSnapshot {
    const { start, end } = range;

    // -- Execution state counts --
    const stateCounts = this.stmtExecutionCounts.all(start, end) as ExecutionCountRow[];
    const stateMap = new Map<string, number>();
    let totalExecutions = 0;
    for (const row of stateCounts) {
      stateMap.set(row.state, row.count);
      totalExecutions += row.count;
    }

    const successfulExecutions = stateMap.get('completed') ?? 0;
    const failedExecutions = stateMap.get('failed') ?? 0;

    // -- Average execution time --
    const avgRow = this.stmtAvgDuration.get(start, end) as AvgDurationRow;
    const avgExecutionTimeMs = avgRow.avg_duration ?? 0;

    // -- MTTD & MTTR --
    const avgMttdMs = this.getMTTD(range);
    const avgMttrMs = this.getMTTR(range);

    // -- Executions by automation level --
    const executionsByLevel = this.getExecutionsByLevel(range);

    // -- Executions by MITRE technique --
    const executionsByTechnique = this.getExecutionsByTechnique(range);

    // -- Top runbooks --
    const topRunbooksRows = this.stmtTopRunbooks.all(start, end) as TopRunbookRow[];
    const topRunbooks = topRunbooksRows.map((r) => ({
      runbook_id: r.runbook_id,
      count: r.count,
    }));

    // -- Adapter health --
    const adapterHealth = this.getAdapterHealthMap();

    return {
      period_start: start,
      period_end: end,
      total_executions: totalExecutions,
      successful_executions: successfulExecutions,
      failed_executions: failedExecutions,
      avg_execution_time_ms: Math.round(avgExecutionTimeMs),
      avg_mttd_ms: Math.round(avgMttdMs),
      avg_mttr_ms: Math.round(avgMttrMs),
      executions_by_level: executionsByLevel,
      executions_by_technique: executionsByTechnique,
      top_runbooks: topRunbooks,
      adapter_health: adapterHealth,
    };
  }

  /**
   * Compute approval latency metrics: avg, median, p95, and per-action averages.
   */
  getApprovalLatency(range: TimeRange): ApprovalLatencyMetrics {
    const rows = this.stmtApprovedEntries.all(
      range.start,
      range.end,
    ) as ApprovalRow[];

    if (rows.length === 0) {
      return {
        avg_latency_ms: 0,
        median_latency_ms: 0,
        p95_latency_ms: 0,
        total_approvals: 0,
        by_action: {},
      };
    }

    // Calculate individual latencies
    const latencies: number[] = [];
    const actionLatencies = new Map<string, number[]>();

    for (const row of rows) {
      const requested = new Date(row.requested_at).getTime();
      const approved = new Date(row.approved_at).getTime();
      const latency = approved - requested;

      if (latency >= 0) {
        latencies.push(latency);

        let actionList = actionLatencies.get(row.action);
        if (!actionList) {
          actionList = [];
          actionLatencies.set(row.action, actionList);
        }
        actionList.push(latency);
      }
    }

    if (latencies.length === 0) {
      return {
        avg_latency_ms: 0,
        median_latency_ms: 0,
        p95_latency_ms: 0,
        total_approvals: 0,
        by_action: {},
      };
    }

    // Sort latencies for percentile calculations
    latencies.sort((a, b) => a - b);

    const avgLatencyMs = latencies.reduce((sum, v) => sum + v, 0) / latencies.length;
    const medianLatencyMs = percentile(latencies, 0.5);
    const p95LatencyMs = percentile(latencies, 0.95);

    // Per-action averages
    const byAction: Record<string, number> = {};
    for (const [action, actionLats] of actionLatencies) {
      byAction[action] = Math.round(
        actionLats.reduce((sum, v) => sum + v, 0) / actionLats.length,
      );
    }

    return {
      avg_latency_ms: Math.round(avgLatencyMs),
      median_latency_ms: Math.round(medianLatencyMs),
      p95_latency_ms: Math.round(p95LatencyMs),
      total_approvals: latencies.length,
      by_action: byAction,
    };
  }

  /**
   * Compute playbook coverage: how many MITRE techniques have mapped playbooks
   * vs. how many have been observed in executions.
   */
  getPlaybookCoverage(range: TimeRange): PlaybookCoverageMetrics {
    const mapped = this.getMappedTechniques();
    const seenTechniques = this.getExecutionsByTechnique(range);

    const seenSet = new Set(Object.keys(seenTechniques));
    const allSeen = new Set(Object.keys(seenTechniques));

    // Find unmapped techniques: seen in executions but not in the map
    const unmapped: string[] = [];
    for (const technique of allSeen) {
      if (!mapped.has(technique)) {
        unmapped.push(technique);
      }
    }

    // Coverage: how many mapped techniques have actually been observed
    const totalMapped = mapped.size;
    const totalSeen = seenSet.size;
    const coveredCount = totalMapped > 0
      ? [...mapped].filter((t) => seenSet.has(t)).length
      : 0;
    const coverageRatio = totalMapped > 0 ? coveredCount / totalMapped : 0;

    // Most used playbooks
    const playbooks = this.stmtPlaybookUsage.all(
      range.start,
      range.end,
    ) as PlaybookUsageRow[];

    const mostUsed = playbooks.map((r) => ({
      runbook_id: r.runbook_id,
      runbook_name: r.runbook_name,
      count: r.count,
    }));

    return {
      total_techniques_mapped: totalMapped,
      total_techniques_seen: totalSeen,
      coverage_ratio: clamp(coverageRatio, 0, 1),
      unmapped_techniques: unmapped.sort(),
      usage_by_technique: seenTechniques,
      most_used_playbooks: mostUsed,
    };
  }

  /**
   * Mean Time to Detect (MTTD): average milliseconds from alert @timestamp
   * to execution started_at.
   *
   * Requires that the execution's context_snapshot JSON contains an `alert`
   * object with an `@timestamp` field, as per the AlertEvent ECS schema.
   */
  getMTTD(range: TimeRange): number {
    const rows = this.stmtContextSnapshots.all(
      range.start,
      range.end,
    ) as ContextSnapshotRow[];

    let totalMs = 0;
    let count = 0;

    for (const row of rows) {
      if (!row.context_snapshot) continue;

      const alertTimestamp = extractAlertTimestamp(row.context_snapshot);
      if (!alertTimestamp) continue;

      const alertTime = new Date(alertTimestamp).getTime();
      const startedTime = new Date(row.started_at).getTime();

      if (Number.isNaN(alertTime) || Number.isNaN(startedTime)) continue;

      const delta = startedTime - alertTime;
      if (delta >= 0) {
        totalMs += delta;
        count++;
      }
    }

    return count > 0 ? totalMs / count : 0;
  }

  /**
   * Mean Time to Respond (MTTR): average milliseconds from execution
   * started_at to completed_at.
   */
  getMTTR(range: TimeRange): number {
    const rows = this.stmtMttrRows.all(range.start, range.end) as MttrRow[];

    let totalMs = 0;
    let count = 0;

    for (const row of rows) {
      const startedTime = new Date(row.started_at).getTime();
      const completedTime = new Date(row.completed_at).getTime();

      if (Number.isNaN(startedTime) || Number.isNaN(completedTime)) continue;

      const delta = completedTime - startedTime;
      if (delta >= 0) {
        totalMs += delta;
        count++;
      }
    }

    return count > 0 ? totalMs / count : 0;
  }

  /**
   * Success rate: ratio of completed executions to total executions (0-1).
   */
  getSuccessRate(range: TimeRange): number {
    const totalRow = this.stmtTotalExecutions.get(
      range.start,
      range.end,
    ) as { count: number };
    const successRow = this.stmtSuccessCount.get(
      range.start,
      range.end,
    ) as { count: number };

    if (totalRow.count === 0) return 0;
    return clamp(successRow.count / totalRow.count, 0, 1);
  }

  /**
   * Persist an aggregated MetricsSnapshot into the `metrics` table.
   * Each scalar metric is stored as its own row with optional JSON dimensions.
   */
  saveMetricsSnapshot(snapshot: MetricsSnapshot): void {
    const { period_start, period_end } = snapshot;

    const insertMetric = this.db.transaction(
      (metrics: Array<{ name: string; value: number; dimensions?: string }>) => {
        for (const m of metrics) {
          this.stmtInsertMetric.run(
            period_start,
            period_end,
            m.name,
            m.value,
            m.dimensions ?? null,
          );
        }
      },
    );

    const metrics: Array<{ name: string; value: number; dimensions?: string }> = [
      { name: 'total_executions', value: snapshot.total_executions },
      { name: 'successful_executions', value: snapshot.successful_executions },
      { name: 'failed_executions', value: snapshot.failed_executions },
      { name: 'avg_execution_time_ms', value: snapshot.avg_execution_time_ms },
      { name: 'avg_mttd_ms', value: snapshot.avg_mttd_ms },
      { name: 'avg_mttr_ms', value: snapshot.avg_mttr_ms },
    ];

    // Executions by level
    for (const [level, count] of Object.entries(snapshot.executions_by_level)) {
      metrics.push({
        name: 'executions_by_level',
        value: count,
        dimensions: JSON.stringify({ level }),
      });
    }

    // Executions by technique
    for (const [technique, count] of Object.entries(snapshot.executions_by_technique)) {
      metrics.push({
        name: 'executions_by_technique',
        value: count,
        dimensions: JSON.stringify({ technique }),
      });
    }

    // Top runbooks
    for (const runbook of snapshot.top_runbooks) {
      metrics.push({
        name: 'top_runbook_count',
        value: runbook.count,
        dimensions: JSON.stringify({ runbook_id: runbook.runbook_id }),
      });
    }

    // Adapter health (encode as numeric: healthy=1, degraded=0.5, unhealthy=0, unknown=-1)
    for (const [adapter, health] of Object.entries(snapshot.adapter_health)) {
      metrics.push({
        name: 'adapter_health',
        value: healthToNumeric(health),
        dimensions: JSON.stringify({ adapter, health }),
      });
    }

    insertMetric(metrics);
  }

  // -----------------------------------------------------------------------
  // Private Helpers
  // -----------------------------------------------------------------------

  /**
   * Count executions grouped by automation level, extracted from context_snapshot JSON.
   * Falls back to counting by execution mode if the level is not available.
   */
  private getExecutionsByLevel(range: TimeRange): Record<AutomationLevel, number> {
    const result: Record<AutomationLevel, number> = { L0: 0, L1: 0, L2: 0 };

    const rows = this.db.prepare(`
      SELECT context_snapshot, mode
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
    `).all(range.start, range.end) as Array<{
      context_snapshot: string | null;
      mode: string;
    }>;

    for (const row of rows) {
      let level: AutomationLevel | null = null;

      // Try to extract automation_level from the context_snapshot JSON
      if (row.context_snapshot) {
        level = extractAutomationLevel(row.context_snapshot);
      }

      // Fallback: infer from execution mode
      if (!level) {
        level = modeToLevel(row.mode);
      }

      result[level]++;
    }

    return result;
  }

  /**
   * Extract MITRE technique IDs from execution context_snapshots and count them.
   */
  private getExecutionsByTechnique(range: TimeRange): Record<string, number> {
    const rows = this.db.prepare(`
      SELECT context_snapshot
      FROM executions
      WHERE started_at >= ? AND started_at <= ?
        AND context_snapshot IS NOT NULL
    `).all(range.start, range.end) as Array<{ context_snapshot: string }>;

    const techniqueCounts: Record<string, number> = {};

    for (const row of rows) {
      const techniques = extractTechniqueIds(row.context_snapshot);
      for (const tid of techniques) {
        techniqueCounts[tid] = (techniqueCounts[tid] ?? 0) + 1;
      }
    }

    return techniqueCounts;
  }

  /**
   * Query adapter health from the adapters table.
   */
  private getAdapterHealthMap(): Record<string, AdapterHealth> {
    const rows = this.stmtAdapterHealth.all() as AdapterHealthRow[];
    const healthMap: Record<string, AdapterHealth> = {};

    for (const row of rows) {
      healthMap[row.name] = (row.health_status as AdapterHealth) ?? 'unknown';
    }

    return healthMap;
  }

  /**
   * Load and cache the set of techniques from config/technique-playbook-map.yml.
   */
  private getMappedTechniques(): Set<string> {
    if (this.mappedTechniques) {
      return this.mappedTechniques;
    }

    const techniqueSet = new Set<string>();

    try {
      // Resolve path relative to the project root
      // __dirname equivalent: walk up from src/metrics/ to project root
      const mapPath = resolve(
        import.meta.dirname ?? '.',
        '..',
        '..',
        'config',
        'technique-playbook-map.yml',
      );

      const content = readFileSync(mapPath, 'utf-8');
      const parsed = YAML.parse(content) as TechniquePlaybookMapFile;

      if (parsed?.mappings && Array.isArray(parsed.mappings)) {
        for (const mapping of parsed.mappings) {
          if (mapping.technique_id) {
            techniqueSet.add(mapping.technique_id);
          }
        }
      }
    } catch {
      // If the map file is not found, return an empty set.
      // This is not an error -- the system can operate without it.
    }

    this.mappedTechniques = techniqueSet;
    return techniqueSet;
  }
}

// ---------------------------------------------------------------------------
// timeRange Helper
// ---------------------------------------------------------------------------

/**
 * Create a TimeRange for common period presets.
 *
 * @param period - One of '24h', '7d', '30d', or 'all'.
 * @returns A TimeRange with ISO8601 start and end timestamps.
 */
export function timeRange(period: '24h' | '7d' | '30d' | 'all'): TimeRange {
  const now = new Date();
  const end = now.toISOString();

  switch (period) {
    case '24h': {
      const start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      return { start: start.toISOString(), end };
    }
    case '7d': {
      const start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      return { start: start.toISOString(), end };
    }
    case '30d': {
      const start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      return { start: start.toISOString(), end };
    }
    case 'all': {
      // Epoch to now covers all possible data
      return { start: '1970-01-01T00:00:00.000Z', end };
    }
  }
}

// ---------------------------------------------------------------------------
// Internal Pure Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the alert @timestamp from a context_snapshot JSON string.
 * The context_snapshot stores an ExecutionContext which has an `alert`
 * field containing an AlertEvent with `@timestamp`.
 */
function extractAlertTimestamp(contextJson: string): string | null {
  try {
    const ctx = JSON.parse(contextJson) as Record<string, unknown>;

    // Direct alert field on the context
    const alert = ctx['alert'] as Record<string, unknown> | undefined;
    if (alert?.['@timestamp']) {
      return alert['@timestamp'] as string;
    }

    // Fallback: check within variables (some implementations nest it)
    const variables = ctx['variables'] as Record<string, unknown> | undefined;
    if (variables?.['alert_timestamp']) {
      return variables['alert_timestamp'] as string;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Extract automation level from a context_snapshot JSON string.
 * Looks for a `config.automation_level` or `automation_level` field,
 * as well as `variables.automation_level`.
 */
function extractAutomationLevel(contextJson: string): AutomationLevel | null {
  try {
    const ctx = JSON.parse(contextJson) as Record<string, unknown>;

    // Check top-level automation_level
    const topLevel = ctx['automation_level'] as string | undefined;
    if (isValidLevel(topLevel)) return topLevel;

    // Check within a nested config object
    const config = ctx['config'] as Record<string, unknown> | undefined;
    const configLevel = config?.['automation_level'] as string | undefined;
    if (isValidLevel(configLevel)) return configLevel;

    // Check within variables
    const variables = ctx['variables'] as Record<string, unknown> | undefined;
    const varLevel = variables?.['automation_level'] as string | undefined;
    if (isValidLevel(varLevel)) return varLevel;

    return null;
  } catch {
    return null;
  }
}

/**
 * Extract MITRE ATT&CK technique IDs from a context_snapshot JSON string.
 * Searches for technique IDs in the standard ECS threat.technique.id path,
 * as well as in variables.mitre_techniques.
 */
function extractTechniqueIds(contextJson: string): string[] {
  try {
    const ctx = JSON.parse(contextJson) as Record<string, unknown>;
    const techniques: string[] = [];

    // ECS path: alert.threat.technique.id
    const alert = ctx['alert'] as Record<string, unknown> | undefined;
    if (alert) {
      const threat = alert['threat'] as Record<string, unknown> | undefined;
      if (threat) {
        const technique = threat['technique'] as Record<string, unknown> | undefined;
        if (technique) {
          const ids = technique['id'];
          if (Array.isArray(ids)) {
            for (const id of ids) {
              if (typeof id === 'string') techniques.push(id);
            }
          } else if (typeof ids === 'string') {
            techniques.push(ids);
          }
        }
      }
    }

    // Variables path: variables.mitre_techniques
    const variables = ctx['variables'] as Record<string, unknown> | undefined;
    if (variables) {
      const mitreTechniques = variables['mitre_techniques'];
      if (Array.isArray(mitreTechniques)) {
        for (const t of mitreTechniques) {
          if (typeof t === 'string' && !techniques.includes(t)) {
            techniques.push(t);
          }
        }
      }
    }

    // Top-level mitre_techniques (some contexts store them here)
    const topMitre = ctx['mitre_techniques'];
    if (Array.isArray(topMitre)) {
      for (const t of topMitre) {
        if (typeof t === 'string' && !techniques.includes(t)) {
          techniques.push(t);
        }
      }
    }

    return techniques;
  } catch {
    return [];
  }
}

/**
 * Check whether a value is a valid AutomationLevel.
 */
function isValidLevel(value: string | undefined): value is AutomationLevel {
  return value === 'L0' || value === 'L1' || value === 'L2';
}

/**
 * Infer an automation level from the execution mode.
 * This is a best-effort fallback when the context_snapshot does not
 * contain an explicit automation_level.
 */
function modeToLevel(mode: string): AutomationLevel {
  switch (mode) {
    case 'dry-run':
      return 'L0';
    case 'production':
      return 'L1';
    case 'simulation':
      return 'L2';
    default:
      return 'L0';
  }
}

/**
 * Compute a percentile value from a sorted array.
 * Uses the "nearest rank" method: index = ceil(p * n) - 1.
 */
function percentile(sortedValues: number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  if (sortedValues.length === 1) return sortedValues[0]!;

  const index = Math.ceil(p * sortedValues.length) - 1;
  const clamped = Math.max(0, Math.min(index, sortedValues.length - 1));
  return sortedValues[clamped]!;
}

/**
 * Clamp a number to [min, max].
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Convert an AdapterHealth string to a numeric value for storage.
 */
function healthToNumeric(health: AdapterHealth): number {
  switch (health) {
    case 'healthy':
      return 1;
    case 'degraded':
      return 0.5;
    case 'unhealthy':
      return 0;
    case 'unknown':
      return -1;
    default:
      return -1;
  }
}

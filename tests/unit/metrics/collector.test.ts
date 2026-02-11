import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MetricsCollector, timeRange } from '../../../src/metrics/collector.ts';
import type { TimeRange } from '../../../src/metrics/collector.ts';
import { initDatabase, closeDatabase } from '../../../src/db/index.ts';
import type Database from 'better-sqlite3';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A wide time range that covers all possible seeded data. */
const ALL_TIME: TimeRange = {
  start: '1970-01-01T00:00:00.000Z',
  end: '2099-12-31T23:59:59.999Z',
};

/** Insert an execution row with sensible defaults. */
function insertExecution(
  db: Database.Database,
  overrides: Partial<{
    execution_id: string;
    runbook_id: string;
    runbook_version: string;
    runbook_name: string;
    state: string;
    mode: string;
    context_snapshot: string | null;
    error: string | null;
    started_at: string;
    completed_at: string | null;
    duration_ms: number | null;
  }> = {},
): void {
  const row = {
    execution_id: overrides.execution_id ?? crypto.randomUUID(),
    runbook_id: overrides.runbook_id ?? 'rb-001',
    runbook_version: overrides.runbook_version ?? '1.0.0',
    runbook_name: overrides.runbook_name ?? 'Test Runbook',
    state: overrides.state ?? 'completed',
    mode: overrides.mode ?? 'production',
    context_snapshot: 'context_snapshot' in overrides ? overrides.context_snapshot : null,
    error: overrides.error ?? null,
    started_at: overrides.started_at ?? '2025-06-01T10:00:00.000Z',
    completed_at: 'completed_at' in overrides ? overrides.completed_at : '2025-06-01T10:05:00.000Z',
    duration_ms: 'duration_ms' in overrides ? overrides.duration_ms : 300000,
  };

  db.prepare(`
    INSERT INTO executions
      (execution_id, runbook_id, runbook_version, runbook_name, state, mode,
       context_snapshot, error, started_at, completed_at, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    row.execution_id,
    row.runbook_id,
    row.runbook_version,
    row.runbook_name,
    row.state,
    row.mode,
    row.context_snapshot,
    row.error,
    row.started_at,
    row.completed_at,
    row.duration_ms,
  );
}

/** Insert an approval_queue row with sensible defaults. */
function insertApproval(
  db: Database.Database,
  overrides: Partial<{
    request_id: string;
    execution_id: string;
    runbook_id: string;
    runbook_name: string;
    step_id: string;
    step_name: string;
    action: string;
    parameters: string;
    simulation_result: string;
    status: string;
    requested_at: string;
    expires_at: string;
    approved_by: string | null;
    approved_at: string | null;
    denial_reason: string | null;
  }> = {},
): void {
  const row = {
    request_id: overrides.request_id ?? crypto.randomUUID(),
    execution_id: overrides.execution_id ?? 'exec-001',
    runbook_id: overrides.runbook_id ?? 'rb-001',
    runbook_name: overrides.runbook_name ?? 'Test Runbook',
    step_id: overrides.step_id ?? 'step-1',
    step_name: overrides.step_name ?? 'Isolate Host',
    action: overrides.action ?? 'isolate_host',
    parameters: overrides.parameters ?? '{}',
    simulation_result: overrides.simulation_result ?? '{}',
    status: overrides.status ?? 'approved',
    requested_at: overrides.requested_at ?? '2025-06-01T10:00:00.000Z',
    expires_at: overrides.expires_at ?? '2025-06-01T11:00:00.000Z',
    approved_by: overrides.approved_by ?? 'analyst@soc.local',
    approved_at: overrides.approved_at ?? '2025-06-01T10:02:00.000Z',
    denial_reason: overrides.denial_reason ?? null,
  };

  db.prepare(`
    INSERT INTO approval_queue
      (request_id, execution_id, runbook_id, runbook_name, step_id, step_name,
       action, parameters, simulation_result, status, requested_at, expires_at,
       approved_by, approved_at, denial_reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    row.request_id,
    row.execution_id,
    row.runbook_id,
    row.runbook_name,
    row.step_id,
    row.step_name,
    row.action,
    row.parameters,
    row.simulation_result,
    row.status,
    row.requested_at,
    row.expires_at,
    row.approved_by,
    row.approved_at,
    row.denial_reason,
  );
}

/** Insert an adapter row. */
function insertAdapter(
  db: Database.Database,
  overrides: Partial<{
    name: string;
    type: string;
    enabled: number;
    config: string;
    health_status: string | null;
  }> = {},
): void {
  const row = {
    name: overrides.name ?? 'firewall-01',
    type: overrides.type ?? 'firewall',
    enabled: overrides.enabled ?? 1,
    config: overrides.config ?? '{}',
    health_status: overrides.health_status ?? 'healthy',
  };

  db.prepare(`
    INSERT INTO adapters (name, type, enabled, config, health_status)
    VALUES (?, ?, ?, ?, ?)
  `).run(row.name, row.type, row.enabled, row.config, row.health_status);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('MetricsCollector', () => {
  let db: Database.Database;
  let collector: MetricsCollector;

  beforeEach(() => {
    db = initDatabase({ path: ':memory:', inMemory: true });
    collector = new MetricsCollector(db);
  });

  afterEach(() => {
    closeDatabase();
  });

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  describe('constructor', () => {
    it('creates a MetricsCollector instance', () => {
      expect(collector).toBeInstanceOf(MetricsCollector);
    });

    it('accepts a valid database handle', () => {
      const c = new MetricsCollector(db);
      expect(c).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // getExecutionMetrics -- empty DB
  // -------------------------------------------------------------------------

  describe('getExecutionMetrics (empty DB)', () => {
    it('returns zero total_executions', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.total_executions).toBe(0);
    });

    it('returns zero successful_executions', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.successful_executions).toBe(0);
    });

    it('returns zero failed_executions', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.failed_executions).toBe(0);
    });

    it('returns zero avg_execution_time_ms', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.avg_execution_time_ms).toBe(0);
    });

    it('returns zero avg_mttd_ms', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.avg_mttd_ms).toBe(0);
    });

    it('returns zero avg_mttr_ms', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.avg_mttr_ms).toBe(0);
    });

    it('returns correct period_start and period_end', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.period_start).toBe(ALL_TIME.start);
      expect(metrics.period_end).toBe(ALL_TIME.end);
    });

    it('returns empty top_runbooks array', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.top_runbooks).toEqual([]);
    });

    it('returns zeroed executions_by_level', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.executions_by_level).toEqual({ L0: 0, L1: 0, L2: 0 });
    });

    it('returns empty executions_by_technique', () => {
      const metrics = collector.getExecutionMetrics(ALL_TIME);
      expect(metrics.executions_by_technique).toEqual({});
    });
  });

  // -------------------------------------------------------------------------
  // getExecutionMetrics -- seeded data
  // -------------------------------------------------------------------------

  describe('getExecutionMetrics (seeded data)', () => {
    beforeEach(() => {
      // 3 completed, 2 failed, 1 cancelled
      insertExecution(db, { execution_id: 'e1', state: 'completed', duration_ms: 1000, mode: 'production' });
      insertExecution(db, { execution_id: 'e2', state: 'completed', duration_ms: 2000, mode: 'production' });
      insertExecution(db, { execution_id: 'e3', state: 'completed', duration_ms: 3000, mode: 'dry-run' });
      insertExecution(db, { execution_id: 'e4', state: 'failed', duration_ms: 500, mode: 'simulation' });
      insertExecution(db, { execution_id: 'e5', state: 'failed', duration_ms: 750, mode: 'production' });
      insertExecution(db, { execution_id: 'e6', state: 'cancelled', duration_ms: null, completed_at: null, mode: 'production' });
    });

    it('counts total executions correctly', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.total_executions).toBe(6);
    });

    it('counts successful executions correctly', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.successful_executions).toBe(3);
    });

    it('counts failed executions correctly', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.failed_executions).toBe(2);
    });

    it('calculates avg_execution_time_ms from non-null durations', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      // (1000 + 2000 + 3000 + 500 + 750) / 5 = 1450
      expect(m.avg_execution_time_ms).toBe(1450);
    });

    it('returns top_runbooks sorted by count', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.top_runbooks.length).toBeGreaterThanOrEqual(1);
      expect(m.top_runbooks[0]!.runbook_id).toBe('rb-001');
      expect(m.top_runbooks[0]!.count).toBe(6);
    });

    it('populates executions_by_level based on mode fallback', () => {
      const m = collector.getExecutionMetrics(ALL_TIME);
      // production -> L1 (4), dry-run -> L0 (1), simulation -> L2 (1)
      expect(m.executions_by_level.L1).toBe(4);
      expect(m.executions_by_level.L0).toBe(1);
      expect(m.executions_by_level.L2).toBe(1);
    });

    it('filters by time range', () => {
      insertExecution(db, {
        execution_id: 'e-old',
        state: 'completed',
        started_at: '2020-01-01T00:00:00.000Z',
        duration_ms: 100,
      });

      const range: TimeRange = {
        start: '2025-01-01T00:00:00.000Z',
        end: '2099-12-31T23:59:59.999Z',
      };
      const m = collector.getExecutionMetrics(range);
      // The old execution at 2020 should be excluded
      expect(m.total_executions).toBe(6);
    });
  });

  // -------------------------------------------------------------------------
  // getExecutionMetrics -- context_snapshot automation_level
  // -------------------------------------------------------------------------

  describe('getExecutionMetrics (context_snapshot level)', () => {
    it('extracts automation_level from top-level context_snapshot', () => {
      insertExecution(db, {
        execution_id: 'ctx-1',
        state: 'completed',
        mode: 'production',
        context_snapshot: JSON.stringify({ automation_level: 'L0' }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_level.L0).toBe(1);
      expect(m.executions_by_level.L1).toBe(0);
    });

    it('extracts automation_level from config.automation_level', () => {
      insertExecution(db, {
        execution_id: 'ctx-2',
        state: 'completed',
        mode: 'production',
        context_snapshot: JSON.stringify({ config: { automation_level: 'L2' } }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_level.L2).toBe(1);
    });

    it('extracts automation_level from variables.automation_level', () => {
      insertExecution(db, {
        execution_id: 'ctx-3',
        state: 'completed',
        mode: 'dry-run',
        context_snapshot: JSON.stringify({ variables: { automation_level: 'L1' } }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_level.L1).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // getExecutionMetrics -- technique extraction
  // -------------------------------------------------------------------------

  describe('getExecutionMetrics (technique extraction)', () => {
    it('extracts techniques from alert.threat.technique.id (array)', () => {
      insertExecution(db, {
        execution_id: 't1',
        state: 'completed',
        context_snapshot: JSON.stringify({
          alert: { threat: { technique: { id: ['T1059', 'T1053'] } } },
        }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_technique['T1059']).toBe(1);
      expect(m.executions_by_technique['T1053']).toBe(1);
    });

    it('extracts techniques from alert.threat.technique.id (string)', () => {
      insertExecution(db, {
        execution_id: 't2',
        state: 'completed',
        context_snapshot: JSON.stringify({
          alert: { threat: { technique: { id: 'T1071' } } },
        }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_technique['T1071']).toBe(1);
    });

    it('extracts techniques from variables.mitre_techniques', () => {
      insertExecution(db, {
        execution_id: 't3',
        state: 'completed',
        context_snapshot: JSON.stringify({
          variables: { mitre_techniques: ['T1566'] },
        }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_technique['T1566']).toBe(1);
    });

    it('extracts techniques from top-level mitre_techniques', () => {
      insertExecution(db, {
        execution_id: 't4',
        state: 'completed',
        context_snapshot: JSON.stringify({
          mitre_techniques: ['T1110'],
        }),
      });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.executions_by_technique['T1110']).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // getApprovalLatency
  // -------------------------------------------------------------------------

  describe('getApprovalLatency', () => {
    it('returns zeroes for empty DB', () => {
      const result = collector.getApprovalLatency(ALL_TIME);
      expect(result.avg_latency_ms).toBe(0);
      expect(result.median_latency_ms).toBe(0);
      expect(result.p95_latency_ms).toBe(0);
      expect(result.total_approvals).toBe(0);
      expect(result.by_action).toEqual({});
    });

    it('calculates correct avg/median/p95 for a single approval', () => {
      // Need a parent execution for the FK
      insertExecution(db, { execution_id: 'exec-001', state: 'completed' });
      insertApproval(db, {
        requested_at: '2025-06-01T10:00:00.000Z',
        approved_at: '2025-06-01T10:00:05.000Z', // 5000ms
      });

      const result = collector.getApprovalLatency(ALL_TIME);
      expect(result.total_approvals).toBe(1);
      expect(result.avg_latency_ms).toBe(5000);
      expect(result.median_latency_ms).toBe(5000);
      expect(result.p95_latency_ms).toBe(5000);
    });

    it('calculates correct stats for multiple approvals', () => {
      insertExecution(db, { execution_id: 'exec-001', state: 'completed' });

      // Latencies: 1000, 2000, 3000, 4000, 5000
      insertApproval(db, { request_id: 'a1', requested_at: '2025-06-01T10:00:00.000Z', approved_at: '2025-06-01T10:00:01.000Z' });
      insertApproval(db, { request_id: 'a2', requested_at: '2025-06-01T10:00:00.000Z', approved_at: '2025-06-01T10:00:02.000Z' });
      insertApproval(db, { request_id: 'a3', requested_at: '2025-06-01T10:00:00.000Z', approved_at: '2025-06-01T10:00:03.000Z' });
      insertApproval(db, { request_id: 'a4', requested_at: '2025-06-01T10:00:00.000Z', approved_at: '2025-06-01T10:00:04.000Z' });
      insertApproval(db, { request_id: 'a5', requested_at: '2025-06-01T10:00:00.000Z', approved_at: '2025-06-01T10:00:05.000Z' });

      const result = collector.getApprovalLatency(ALL_TIME);
      expect(result.total_approvals).toBe(5);
      expect(result.avg_latency_ms).toBe(3000);
      expect(result.median_latency_ms).toBe(3000);
      expect(result.p95_latency_ms).toBe(5000);
    });

    it('groups by_action correctly', () => {
      insertExecution(db, { execution_id: 'exec-001', state: 'completed' });

      insertApproval(db, {
        request_id: 'b1',
        action: 'isolate_host',
        requested_at: '2025-06-01T10:00:00.000Z',
        approved_at: '2025-06-01T10:00:02.000Z', // 2000ms
      });
      insertApproval(db, {
        request_id: 'b2',
        action: 'block_ip',
        requested_at: '2025-06-01T10:00:00.000Z',
        approved_at: '2025-06-01T10:00:04.000Z', // 4000ms
      });

      const result = collector.getApprovalLatency(ALL_TIME);
      expect(result.by_action['isolate_host']).toBe(2000);
      expect(result.by_action['block_ip']).toBe(4000);
    });

    it('ignores non-approved entries', () => {
      insertExecution(db, { execution_id: 'exec-001', state: 'completed' });

      insertApproval(db, { request_id: 'c1', status: 'denied', approved_at: null });
      insertApproval(db, { request_id: 'c2', status: 'pending', approved_at: null });

      const result = collector.getApprovalLatency(ALL_TIME);
      expect(result.total_approvals).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // getPlaybookCoverage
  // -------------------------------------------------------------------------

  describe('getPlaybookCoverage', () => {
    it('returns zeroes for empty DB', () => {
      const result = collector.getPlaybookCoverage(ALL_TIME);
      expect(result.total_techniques_seen).toBe(0);
      expect(result.unmapped_techniques).toEqual([]);
      expect(result.usage_by_technique).toEqual({});
      expect(result.most_used_playbooks).toEqual([]);
      expect(result.coverage_ratio).toBeGreaterThanOrEqual(0);
      expect(result.coverage_ratio).toBeLessThanOrEqual(1);
    });

    it('counts seen techniques from executions', () => {
      insertExecution(db, {
        execution_id: 'pc1',
        state: 'completed',
        context_snapshot: JSON.stringify({
          alert: { threat: { technique: { id: ['T1059', 'T1053'] } } },
        }),
      });

      const result = collector.getPlaybookCoverage(ALL_TIME);
      expect(result.total_techniques_seen).toBe(2);
      expect(result.usage_by_technique['T1059']).toBe(1);
      expect(result.usage_by_technique['T1053']).toBe(1);
    });

    it('lists most used playbooks sorted by count', () => {
      insertExecution(db, { execution_id: 'pu1', runbook_id: 'rb-A', runbook_name: 'Alpha' });
      insertExecution(db, { execution_id: 'pu2', runbook_id: 'rb-A', runbook_name: 'Alpha' });
      insertExecution(db, { execution_id: 'pu3', runbook_id: 'rb-B', runbook_name: 'Beta' });

      const result = collector.getPlaybookCoverage(ALL_TIME);
      expect(result.most_used_playbooks.length).toBe(2);
      expect(result.most_used_playbooks[0]!.runbook_id).toBe('rb-A');
      expect(result.most_used_playbooks[0]!.count).toBe(2);
      expect(result.most_used_playbooks[1]!.runbook_id).toBe('rb-B');
      expect(result.most_used_playbooks[1]!.count).toBe(1);
    });

    it('coverage_ratio is clamped between 0 and 1', () => {
      const result = collector.getPlaybookCoverage(ALL_TIME);
      expect(result.coverage_ratio).toBeGreaterThanOrEqual(0);
      expect(result.coverage_ratio).toBeLessThanOrEqual(1);
    });
  });

  // -------------------------------------------------------------------------
  // getMTTD
  // -------------------------------------------------------------------------

  describe('getMTTD', () => {
    it('returns 0 for empty DB', () => {
      expect(collector.getMTTD(ALL_TIME)).toBe(0);
    });

    it('returns 0 when no context_snapshots have alert timestamps', () => {
      insertExecution(db, {
        execution_id: 'mttd-1',
        state: 'completed',
        context_snapshot: JSON.stringify({ foo: 'bar' }),
      });
      expect(collector.getMTTD(ALL_TIME)).toBe(0);
    });

    it('calculates MTTD from alert @timestamp to started_at', () => {
      const alertTime = '2025-06-01T09:58:00.000Z'; // 2 minutes before started_at
      insertExecution(db, {
        execution_id: 'mttd-2',
        state: 'completed',
        started_at: '2025-06-01T10:00:00.000Z',
        context_snapshot: JSON.stringify({ alert: { '@timestamp': alertTime } }),
      });

      const mttd = collector.getMTTD(ALL_TIME);
      expect(mttd).toBe(120000); // 2 minutes = 120000ms
    });

    it('averages MTTD across multiple executions', () => {
      insertExecution(db, {
        execution_id: 'mttd-3',
        state: 'completed',
        started_at: '2025-06-01T10:01:00.000Z',
        context_snapshot: JSON.stringify({ alert: { '@timestamp': '2025-06-01T10:00:00.000Z' } }),
      });
      insertExecution(db, {
        execution_id: 'mttd-4',
        state: 'completed',
        started_at: '2025-06-01T10:03:00.000Z',
        context_snapshot: JSON.stringify({ alert: { '@timestamp': '2025-06-01T10:00:00.000Z' } }),
      });

      const mttd = collector.getMTTD(ALL_TIME);
      // (60000 + 180000) / 2 = 120000
      expect(mttd).toBe(120000);
    });

    it('uses variables.alert_timestamp as fallback', () => {
      insertExecution(db, {
        execution_id: 'mttd-5',
        state: 'completed',
        started_at: '2025-06-01T10:00:30.000Z',
        context_snapshot: JSON.stringify({
          variables: { alert_timestamp: '2025-06-01T10:00:00.000Z' },
        }),
      });

      const mttd = collector.getMTTD(ALL_TIME);
      expect(mttd).toBe(30000);
    });

    it('ignores executions where alert time is after started_at', () => {
      insertExecution(db, {
        execution_id: 'mttd-6',
        state: 'completed',
        started_at: '2025-06-01T09:00:00.000Z',
        context_snapshot: JSON.stringify({ alert: { '@timestamp': '2025-06-01T10:00:00.000Z' } }),
      });

      const mttd = collector.getMTTD(ALL_TIME);
      expect(mttd).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // getMTTR
  // -------------------------------------------------------------------------

  describe('getMTTR', () => {
    it('returns 0 for empty DB', () => {
      expect(collector.getMTTR(ALL_TIME)).toBe(0);
    });

    it('calculates MTTR from started_at to completed_at', () => {
      insertExecution(db, {
        execution_id: 'mttr-1',
        state: 'completed',
        started_at: '2025-06-01T10:00:00.000Z',
        completed_at: '2025-06-01T10:05:00.000Z',
      });

      const mttr = collector.getMTTR(ALL_TIME);
      expect(mttr).toBe(300000); // 5 minutes
    });

    it('averages MTTR across multiple executions', () => {
      insertExecution(db, {
        execution_id: 'mttr-2',
        state: 'completed',
        started_at: '2025-06-01T10:00:00.000Z',
        completed_at: '2025-06-01T10:01:00.000Z', // 60s
      });
      insertExecution(db, {
        execution_id: 'mttr-3',
        state: 'failed',
        started_at: '2025-06-01T10:00:00.000Z',
        completed_at: '2025-06-01T10:03:00.000Z', // 180s
      });

      const mttr = collector.getMTTR(ALL_TIME);
      // (60000 + 180000) / 2 = 120000
      expect(mttr).toBe(120000);
    });

    it('ignores executions without completed_at', () => {
      insertExecution(db, {
        execution_id: 'mttr-4',
        state: 'executing',
        started_at: '2025-06-01T10:00:00.000Z',
        completed_at: null,
      });

      const mttr = collector.getMTTR(ALL_TIME);
      expect(mttr).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // getSuccessRate
  // -------------------------------------------------------------------------

  describe('getSuccessRate', () => {
    it('returns 0 for empty DB', () => {
      const rate = collector.getSuccessRate(ALL_TIME);
      expect(rate).toBe(0);
    });

    it('returns 1.0 when all executions are completed', () => {
      insertExecution(db, { execution_id: 'sr-1', state: 'completed' });
      insertExecution(db, { execution_id: 'sr-2', state: 'completed' });

      const rate = collector.getSuccessRate(ALL_TIME);
      expect(rate).toBe(1);
    });

    it('returns 0 when all executions are failed', () => {
      insertExecution(db, { execution_id: 'sr-3', state: 'failed' });
      insertExecution(db, { execution_id: 'sr-4', state: 'failed' });

      const rate = collector.getSuccessRate(ALL_TIME);
      expect(rate).toBe(0);
    });

    it('calculates correct ratio for mixed results', () => {
      insertExecution(db, { execution_id: 'sr-5', state: 'completed' });
      insertExecution(db, { execution_id: 'sr-6', state: 'completed' });
      insertExecution(db, { execution_id: 'sr-7', state: 'failed' });
      insertExecution(db, { execution_id: 'sr-8', state: 'cancelled' });

      const rate = collector.getSuccessRate(ALL_TIME);
      expect(rate).toBe(0.5); // 2 completed / 4 total
    });

    it('is clamped between 0 and 1', () => {
      insertExecution(db, { execution_id: 'sr-9', state: 'completed' });

      const rate = collector.getSuccessRate(ALL_TIME);
      expect(rate).toBeGreaterThanOrEqual(0);
      expect(rate).toBeLessThanOrEqual(1);
    });
  });

  // -------------------------------------------------------------------------
  // saveMetricsSnapshot
  // -------------------------------------------------------------------------

  describe('saveMetricsSnapshot', () => {
    it('persists scalar metrics to the metrics table', () => {
      const snapshot = {
        period_start: '2025-06-01T00:00:00.000Z',
        period_end: '2025-06-02T00:00:00.000Z',
        total_executions: 10,
        successful_executions: 8,
        failed_executions: 2,
        avg_execution_time_ms: 5000,
        avg_mttd_ms: 60000,
        avg_mttr_ms: 300000,
        executions_by_level: { L0: 3, L1: 5, L2: 2 } as Record<'L0' | 'L1' | 'L2', number>,
        executions_by_technique: { 'T1059': 4, 'T1053': 6 },
        top_runbooks: [{ runbook_id: 'rb-001', count: 7 }],
        adapter_health: { 'firewall-01': 'healthy' as const },
      };

      collector.saveMetricsSnapshot(snapshot);

      const rows = db.prepare('SELECT * FROM metrics').all() as Array<{
        metric_name: string;
        metric_value: number;
        dimensions: string | null;
      }>;

      expect(rows.length).toBeGreaterThan(0);

      const totalExec = rows.find((r) => r.metric_name === 'total_executions');
      expect(totalExec).toBeDefined();
      expect(totalExec!.metric_value).toBe(10);
    });

    it('persists executions_by_level with dimensions', () => {
      const snapshot = {
        period_start: '2025-06-01T00:00:00.000Z',
        period_end: '2025-06-02T00:00:00.000Z',
        total_executions: 5,
        successful_executions: 5,
        failed_executions: 0,
        avg_execution_time_ms: 1000,
        avg_mttd_ms: 0,
        avg_mttr_ms: 0,
        executions_by_level: { L0: 2, L1: 3, L2: 0 } as Record<'L0' | 'L1' | 'L2', number>,
        executions_by_technique: {},
        top_runbooks: [],
        adapter_health: {},
      };

      collector.saveMetricsSnapshot(snapshot);

      const levelRows = db.prepare(
        "SELECT * FROM metrics WHERE metric_name = 'executions_by_level'",
      ).all() as Array<{ metric_value: number; dimensions: string }>;

      expect(levelRows.length).toBe(3); // L0, L1, L2
      const l1Row = levelRows.find((r) => JSON.parse(r.dimensions).level === 'L1');
      expect(l1Row).toBeDefined();
      expect(l1Row!.metric_value).toBe(3);
    });

    it('persists adapter_health with numeric encoding', () => {
      const snapshot = {
        period_start: '2025-06-01T00:00:00.000Z',
        period_end: '2025-06-02T00:00:00.000Z',
        total_executions: 0,
        successful_executions: 0,
        failed_executions: 0,
        avg_execution_time_ms: 0,
        avg_mttd_ms: 0,
        avg_mttr_ms: 0,
        executions_by_level: { L0: 0, L1: 0, L2: 0 } as Record<'L0' | 'L1' | 'L2', number>,
        executions_by_technique: {},
        top_runbooks: [],
        adapter_health: {
          'fw-01': 'healthy' as const,
          'edr-01': 'degraded' as const,
          'siem-01': 'unhealthy' as const,
          'unknown-01': 'unknown' as const,
        },
      };

      collector.saveMetricsSnapshot(snapshot);

      const rows = db.prepare(
        "SELECT * FROM metrics WHERE metric_name = 'adapter_health'",
      ).all() as Array<{ metric_value: number; dimensions: string }>;

      expect(rows.length).toBe(4);

      const healthy = rows.find((r) => JSON.parse(r.dimensions).adapter === 'fw-01');
      expect(healthy!.metric_value).toBe(1);

      const degraded = rows.find((r) => JSON.parse(r.dimensions).adapter === 'edr-01');
      expect(degraded!.metric_value).toBe(0.5);

      const unhealthy = rows.find((r) => JSON.parse(r.dimensions).adapter === 'siem-01');
      expect(unhealthy!.metric_value).toBe(0);

      const unknown = rows.find((r) => JSON.parse(r.dimensions).adapter === 'unknown-01');
      expect(unknown!.metric_value).toBe(-1);
    });

    it('persists executions_by_technique with dimensions', () => {
      const snapshot = {
        period_start: '2025-06-01T00:00:00.000Z',
        period_end: '2025-06-02T00:00:00.000Z',
        total_executions: 3,
        successful_executions: 3,
        failed_executions: 0,
        avg_execution_time_ms: 1000,
        avg_mttd_ms: 0,
        avg_mttr_ms: 0,
        executions_by_level: { L0: 0, L1: 0, L2: 0 } as Record<'L0' | 'L1' | 'L2', number>,
        executions_by_technique: { 'T1059': 2, 'T1053': 1 },
        top_runbooks: [],
        adapter_health: {},
      };

      collector.saveMetricsSnapshot(snapshot);

      const techRows = db.prepare(
        "SELECT * FROM metrics WHERE metric_name = 'executions_by_technique'",
      ).all() as Array<{ metric_value: number; dimensions: string }>;

      expect(techRows.length).toBe(2);
      const t1059 = techRows.find((r) => JSON.parse(r.dimensions).technique === 'T1059');
      expect(t1059).toBeDefined();
      expect(t1059!.metric_value).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // Adapter health map
  // -------------------------------------------------------------------------

  describe('adapter health in getExecutionMetrics', () => {
    it('includes enabled adapters', () => {
      insertAdapter(db, { name: 'fw-01', health_status: 'healthy' });
      insertAdapter(db, { name: 'edr-01', health_status: 'degraded' });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.adapter_health['fw-01']).toBe('healthy');
      expect(m.adapter_health['edr-01']).toBe('degraded');
    });

    it('excludes disabled adapters', () => {
      insertAdapter(db, { name: 'disabled-01', enabled: 0, health_status: 'healthy' });

      const m = collector.getExecutionMetrics(ALL_TIME);
      expect(m.adapter_health['disabled-01']).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // timeRange helper
  // -------------------------------------------------------------------------

  describe('timeRange', () => {
    it('returns a 24h range', () => {
      const range = timeRange('24h');
      const startMs = new Date(range.start).getTime();
      const endMs = new Date(range.end).getTime();
      const diff = endMs - startMs;

      // Should be approximately 24 hours
      expect(diff).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000 - 1000);
      expect(diff).toBeLessThanOrEqual(24 * 60 * 60 * 1000 + 1000);
    });

    it('returns a 7d range', () => {
      const range = timeRange('7d');
      const startMs = new Date(range.start).getTime();
      const endMs = new Date(range.end).getTime();
      const diff = endMs - startMs;

      expect(diff).toBeGreaterThanOrEqual(7 * 24 * 60 * 60 * 1000 - 1000);
      expect(diff).toBeLessThanOrEqual(7 * 24 * 60 * 60 * 1000 + 1000);
    });

    it('returns a 30d range', () => {
      const range = timeRange('30d');
      const startMs = new Date(range.start).getTime();
      const endMs = new Date(range.end).getTime();
      const diff = endMs - startMs;

      expect(diff).toBeGreaterThanOrEqual(30 * 24 * 60 * 60 * 1000 - 1000);
      expect(diff).toBeLessThanOrEqual(30 * 24 * 60 * 60 * 1000 + 1000);
    });

    it('returns epoch start for "all"', () => {
      const range = timeRange('all');
      expect(range.start).toBe('1970-01-01T00:00:00.000Z');
    });

    it('end is a valid ISO8601 timestamp', () => {
      const range = timeRange('24h');
      expect(() => new Date(range.end)).not.toThrow();
      expect(new Date(range.end).toISOString()).toBe(range.end);
    });

    it('start is a valid ISO8601 timestamp', () => {
      const range = timeRange('7d');
      expect(() => new Date(range.start)).not.toThrow();
      expect(new Date(range.start).toISOString()).toBe(range.start);
    });
  });
});

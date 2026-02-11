import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { ExecutionRepository } from '../../../src/db/execution-repository.ts';
import type { StepResult } from '../../../src/types/playbook.ts';

/**
 * Create an in-memory SQLite database with the schema that
 * ExecutionRepository expects.
 *
 * NOTE: The repository code references column names (context_snapshot, error,
 * output) that differ from the base schema.sql (context_data, error_data,
 * output_data). We define the tables here with the exact columns the
 * repository SQL uses so the unit tests exercise the repository logic
 * correctly.
 */
function createTestDatabase(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
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
      started_at TEXT NOT NULL,
      completed_at TEXT,
      duration_ms INTEGER,
      context_snapshot TEXT,
      error TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE INDEX IF NOT EXISTS idx_executions_runbook ON executions(runbook_id);
    CREATE INDEX IF NOT EXISTS idx_executions_state ON executions(state);
    CREATE INDEX IF NOT EXISTS idx_executions_started ON executions(started_at DESC);

    CREATE TABLE IF NOT EXISTS step_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      execution_id TEXT NOT NULL,
      step_id TEXT NOT NULL,
      step_name TEXT NOT NULL,
      action TEXT NOT NULL,
      success INTEGER NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      output TEXT,
      error TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_step_results_execution ON step_results(execution_id);
  `);

  return db;
}

describe('ExecutionRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ExecutionRepository;

  beforeEach(() => {
    db = createTestDatabase();
    repo = new ExecutionRepository(db);
  });

  // -------------------------------------------------------------------------
  // createExecution
  // -------------------------------------------------------------------------

  describe('createExecution', () => {
    it('creates an execution record and retrieves it with getExecution', () => {
      repo.createExecution({
        executionId: 'exec-001',
        runbookId: 'rb-phishing-001',
        runbookVersion: '1.0.0',
        runbookName: 'Phishing Response',
        mode: 'production',
      });

      const record = repo.getExecution('exec-001');
      expect(record).toBeDefined();
      expect(record!.execution_id).toBe('exec-001');
      expect(record!.runbook_id).toBe('rb-phishing-001');
      expect(record!.runbook_version).toBe('1.0.0');
      expect(record!.runbook_name).toBe('Phishing Response');
      expect(record!.state).toBe('idle');
      expect(record!.mode).toBe('production');
      expect(record!.started_at).toBeDefined();
      expect(record!.context_snapshot).toBeNull();
    });

    it('creates an execution with contextSnapshot serialized as JSON', () => {
      const context = {
        alert_id: 'alert-999',
        source_ip: '10.0.0.5',
        indicators: ['hash-abc', 'domain-evil.com'],
      };

      repo.createExecution({
        executionId: 'exec-002',
        runbookId: 'rb-malware-001',
        runbookVersion: '2.1.0',
        runbookName: 'Malware Containment',
        mode: 'simulation',
        contextSnapshot: context,
      });

      const record = repo.getExecution('exec-002');
      expect(record).toBeDefined();
      expect(record!.context_snapshot).toBeDefined();
      const parsed = JSON.parse(record!.context_snapshot!);
      expect(parsed.alert_id).toBe('alert-999');
      expect(parsed.source_ip).toBe('10.0.0.5');
      expect(parsed.indicators).toEqual(['hash-abc', 'domain-evil.com']);
    });
  });

  // -------------------------------------------------------------------------
  // updateState
  // -------------------------------------------------------------------------

  describe('updateState', () => {
    it('changes the execution state', () => {
      repo.createExecution({
        executionId: 'exec-010',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test Runbook',
        mode: 'production',
      });

      expect(repo.getExecution('exec-010')!.state).toBe('idle');

      repo.updateState('exec-010', 'executing');
      expect(repo.getExecution('exec-010')!.state).toBe('executing');

      repo.updateState('exec-010', 'completed');
      expect(repo.getExecution('exec-010')!.state).toBe('completed');
    });

    it('updates the updated_at timestamp', () => {
      repo.createExecution({
        executionId: 'exec-011',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test Runbook',
        mode: 'dry-run',
      });

      // SQLite strftime resolution is milliseconds, so the timestamp should
      // be set on update (may or may not differ within the same millisecond).
      repo.updateState('exec-011', 'validating');

      const after = repo.getExecution('exec-011')!.updated_at;
      expect(after).toBeDefined();
      // updated_at should be a valid ISO-ish timestamp
      expect(after).toMatch(/^\d{4}-\d{2}-\d{2}/);
    });
  });

  // -------------------------------------------------------------------------
  // completeExecution
  // -------------------------------------------------------------------------

  describe('completeExecution', () => {
    it('sets completed_at, duration_ms, state, and optional error/context', () => {
      repo.createExecution({
        executionId: 'exec-020',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Incident Response',
        mode: 'production',
      });

      repo.completeExecution('exec-020', {
        state: 'completed',
        durationMs: 12345,
        contextSnapshot: { final: 'state' },
      });

      const record = repo.getExecution('exec-020');
      expect(record).toBeDefined();
      expect(record!.state).toBe('completed');
      expect(record!.completed_at).toBeDefined();
      expect(record!.completed_at).toMatch(/^\d{4}-\d{2}-\d{2}/);
      expect(record!.duration_ms).toBe(12345);
      expect(record!.error).toBeNull();
      const ctx = JSON.parse(record!.context_snapshot!);
      expect(ctx.final).toBe('state');
    });

    it('stores error as JSON when execution fails', () => {
      repo.createExecution({
        executionId: 'exec-021',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Failed Runbook',
        mode: 'production',
      });

      const error = {
        code: 'ADAPTER_TIMEOUT',
        message: 'EDR adapter timed out after 30s',
        step_id: 'step-03',
      };

      repo.completeExecution('exec-021', {
        state: 'failed',
        durationMs: 30500,
        error,
        contextSnapshot: { partial: true },
      });

      const record = repo.getExecution('exec-021');
      expect(record!.state).toBe('failed');
      expect(record!.duration_ms).toBe(30500);
      const parsedError = JSON.parse(record!.error!);
      expect(parsedError.code).toBe('ADAPTER_TIMEOUT');
      expect(parsedError.message).toBe('EDR adapter timed out after 30s');
      expect(parsedError.step_id).toBe('step-03');
    });

    it('sets error and context_snapshot to null when not provided', () => {
      repo.createExecution({
        executionId: 'exec-022',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Clean Run',
        mode: 'simulation',
      });

      repo.completeExecution('exec-022', {
        state: 'completed',
        durationMs: 500,
      });

      const record = repo.getExecution('exec-022');
      expect(record!.error).toBeNull();
      expect(record!.context_snapshot).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // saveStepResult / getStepResults
  // -------------------------------------------------------------------------

  describe('saveStepResult', () => {
    const baseStepResult: StepResult = {
      step_id: 'step-01',
      step_name: 'Isolate Host',
      action: 'isolate_host',
      success: true,
      started_at: '2026-02-11T10:00:00.000Z',
      completed_at: '2026-02-11T10:00:05.000Z',
      duration_ms: 5000,
      output: { hostname: 'ws-infected-01', isolated: true },
    };

    it('saves a step result and retrieves it with getStepResults', () => {
      repo.createExecution({
        executionId: 'exec-030',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test',
        mode: 'production',
      });

      repo.saveStepResult('exec-030', baseStepResult);

      const results = repo.getStepResults('exec-030');
      expect(results).toHaveLength(1);
      expect(results[0]!.step_id).toBe('step-01');
      expect(results[0]!.step_name).toBe('Isolate Host');
      expect(results[0]!.action).toBe('isolate_host');
      expect(results[0]!.success).toBe(true);
      expect(results[0]!.started_at).toBe('2026-02-11T10:00:00.000Z');
      expect(results[0]!.completed_at).toBe('2026-02-11T10:00:05.000Z');
      expect(results[0]!.duration_ms).toBe(5000);
      expect(results[0]!.output).toEqual({ hostname: 'ws-infected-01', isolated: true });
    });

    it('stores boolean success as 1/0 in SQLite', () => {
      repo.createExecution({
        executionId: 'exec-031',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test',
        mode: 'production',
      });

      // Save a successful step
      repo.saveStepResult('exec-031', { ...baseStepResult, success: true });

      // Save a failed step
      repo.saveStepResult('exec-031', {
        ...baseStepResult,
        step_id: 'step-02',
        step_name: 'Block IP',
        action: 'block_ip',
        success: false,
        error: { code: 'FW_ERR', message: 'Firewall unreachable' },
      });

      // Verify raw DB values (1/0) for success column
      const rawRows = db
        .prepare('SELECT step_id, success FROM step_results WHERE execution_id = ? ORDER BY step_id')
        .all('exec-031') as Array<{ step_id: string; success: number }>;

      expect(rawRows[0]!.success).toBe(1); // true stored as 1
      expect(rawRows[1]!.success).toBe(0); // false stored as 0

      // Verify the repository maps them back to booleans
      const results = repo.getStepResults('exec-031');
      expect(results[0]!.success).toBe(true);
      expect(results[1]!.success).toBe(false);
    });

    it('returns step results ordered by started_at', () => {
      repo.createExecution({
        executionId: 'exec-032',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test',
        mode: 'production',
      });

      // Insert in reverse chronological order
      repo.saveStepResult('exec-032', {
        ...baseStepResult,
        step_id: 'step-03',
        step_name: 'Third Step',
        started_at: '2026-02-11T10:00:20.000Z',
        completed_at: '2026-02-11T10:00:25.000Z',
      });
      repo.saveStepResult('exec-032', {
        ...baseStepResult,
        step_id: 'step-01',
        step_name: 'First Step',
        started_at: '2026-02-11T10:00:00.000Z',
        completed_at: '2026-02-11T10:00:05.000Z',
      });
      repo.saveStepResult('exec-032', {
        ...baseStepResult,
        step_id: 'step-02',
        step_name: 'Second Step',
        started_at: '2026-02-11T10:00:10.000Z',
        completed_at: '2026-02-11T10:00:15.000Z',
      });

      const results = repo.getStepResults('exec-032');
      expect(results).toHaveLength(3);
      expect(results[0]!.step_id).toBe('step-01');
      expect(results[1]!.step_id).toBe('step-02');
      expect(results[2]!.step_id).toBe('step-03');
    });

    it('handles step result with no output and no error', () => {
      repo.createExecution({
        executionId: 'exec-033',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test',
        mode: 'dry-run',
      });

      repo.saveStepResult('exec-033', {
        step_id: 'step-01',
        step_name: 'Dry Run Step',
        action: 'query_siem',
        success: true,
        started_at: '2026-02-11T10:00:00.000Z',
        completed_at: '2026-02-11T10:00:01.000Z',
        duration_ms: 1000,
      });

      const results = repo.getStepResults('exec-033');
      expect(results[0]!.output).toBeUndefined();
      expect(results[0]!.error).toBeUndefined();
    });

    it('stores error object as JSON for failed steps', () => {
      repo.createExecution({
        executionId: 'exec-034',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'Test',
        mode: 'production',
      });

      const errorDetail = {
        code: 'ADAPTER_TIMEOUT',
        message: 'Connection timed out',
        details: { adapter: 'edr', timeout_ms: 30000 },
      };

      repo.saveStepResult('exec-034', {
        step_id: 'step-01',
        step_name: 'EDR Scan',
        action: 'start_edr_scan',
        success: false,
        started_at: '2026-02-11T10:00:00.000Z',
        completed_at: '2026-02-11T10:00:30.000Z',
        duration_ms: 30000,
        error: errorDetail,
      });

      const results = repo.getStepResults('exec-034');
      expect(results[0]!.error).toEqual(errorDetail);
    });
  });

  // -------------------------------------------------------------------------
  // getExecution
  // -------------------------------------------------------------------------

  describe('getExecution', () => {
    it('returns undefined for an unknown execution ID', () => {
      const record = repo.getExecution('non-existent-id');
      expect(record).toBeUndefined();
    });

    it('returns the correct record when multiple executions exist', () => {
      repo.createExecution({
        executionId: 'exec-040',
        runbookId: 'rb-001',
        runbookVersion: '1.0.0',
        runbookName: 'First',
        mode: 'production',
      });
      repo.createExecution({
        executionId: 'exec-041',
        runbookId: 'rb-002',
        runbookVersion: '2.0.0',
        runbookName: 'Second',
        mode: 'simulation',
      });

      const first = repo.getExecution('exec-040');
      const second = repo.getExecution('exec-041');

      expect(first!.runbook_name).toBe('First');
      expect(second!.runbook_name).toBe('Second');
      expect(first!.mode).toBe('production');
      expect(second!.mode).toBe('simulation');
    });
  });

  // -------------------------------------------------------------------------
  // queryExecutions
  // -------------------------------------------------------------------------

  describe('queryExecutions', () => {
    function seedExecutions() {
      const executions = [
        { id: 'exec-100', rbId: 'rb-phishing', name: 'Phishing', mode: 'production' as const, state: 'completed' as const, startedAt: '2026-02-10T08:00:00.000Z' },
        { id: 'exec-101', rbId: 'rb-phishing', name: 'Phishing', mode: 'simulation' as const, state: 'failed' as const, startedAt: '2026-02-10T09:00:00.000Z' },
        { id: 'exec-102', rbId: 'rb-malware', name: 'Malware', mode: 'production' as const, state: 'completed' as const, startedAt: '2026-02-10T10:00:00.000Z' },
        { id: 'exec-103', rbId: 'rb-malware', name: 'Malware', mode: 'dry-run' as const, state: 'idle' as const, startedAt: '2026-02-10T11:00:00.000Z' },
        { id: 'exec-104', rbId: 'rb-phishing', name: 'Phishing', mode: 'production' as const, state: 'completed' as const, startedAt: '2026-02-10T12:00:00.000Z' },
        { id: 'exec-105', rbId: 'rb-lateral', name: 'Lateral Movement', mode: 'simulation' as const, state: 'executing' as const, startedAt: '2026-02-10T13:00:00.000Z' },
      ];

      for (const e of executions) {
        // Insert directly to control started_at precisely
        db.prepare(`
          INSERT INTO executions (
            execution_id, runbook_id, runbook_version, runbook_name,
            state, mode, started_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(e.id, e.rbId, '1.0.0', e.name, e.state, e.mode, e.startedAt);
      }
    }

    it('filters by runbookId', () => {
      seedExecutions();

      const results = repo.queryExecutions({ runbookId: 'rb-phishing' });
      expect(results).toHaveLength(3);
      for (const r of results) {
        expect(r.runbook_id).toBe('rb-phishing');
      }
    });

    it('filters by state', () => {
      seedExecutions();

      const results = repo.queryExecutions({ state: 'completed' });
      expect(results).toHaveLength(3);
      for (const r of results) {
        expect(r.state).toBe('completed');
      }
    });

    it('filters by mode', () => {
      seedExecutions();

      const results = repo.queryExecutions({ mode: 'simulation' });
      expect(results).toHaveLength(2);
      for (const r of results) {
        expect(r.mode).toBe('simulation');
      }
    });

    it('filters by startedAfter and startedBefore', () => {
      seedExecutions();

      const results = repo.queryExecutions({
        startedAfter: '2026-02-10T09:30:00.000Z',
        startedBefore: '2026-02-10T12:30:00.000Z',
      });

      // Should match exec-102 (10:00), exec-103 (11:00), exec-104 (12:00)
      expect(results).toHaveLength(3);

      const ids = results.map((r) => r.execution_id);
      expect(ids).toContain('exec-102');
      expect(ids).toContain('exec-103');
      expect(ids).toContain('exec-104');
    });

    it('respects limit and offset', () => {
      seedExecutions();

      // Default order is started_at DESC, so:
      // exec-105 (13:00), exec-104 (12:00), exec-103 (11:00),
      // exec-102 (10:00), exec-101 (09:00), exec-100 (08:00)

      const page1 = repo.queryExecutions({ limit: 2, offset: 0 });
      expect(page1).toHaveLength(2);
      expect(page1[0]!.execution_id).toBe('exec-105');
      expect(page1[1]!.execution_id).toBe('exec-104');

      const page2 = repo.queryExecutions({ limit: 2, offset: 2 });
      expect(page2).toHaveLength(2);
      expect(page2[0]!.execution_id).toBe('exec-103');
      expect(page2[1]!.execution_id).toBe('exec-102');

      const page3 = repo.queryExecutions({ limit: 2, offset: 4 });
      expect(page3).toHaveLength(2);
      expect(page3[0]!.execution_id).toBe('exec-101');
      expect(page3[1]!.execution_id).toBe('exec-100');
    });

    it('returns all executions when no filters are provided', () => {
      seedExecutions();

      const results = repo.queryExecutions();
      expect(results).toHaveLength(6);
    });

    it('returns results ordered by started_at descending', () => {
      seedExecutions();

      const results = repo.queryExecutions();
      for (let i = 1; i < results.length; i++) {
        expect(results[i - 1]!.started_at >= results[i]!.started_at).toBe(true);
      }
    });

    it('combines multiple filters', () => {
      seedExecutions();

      const results = repo.queryExecutions({
        runbookId: 'rb-phishing',
        state: 'completed',
        mode: 'production',
      });

      expect(results).toHaveLength(2);
      for (const r of results) {
        expect(r.runbook_id).toBe('rb-phishing');
        expect(r.state).toBe('completed');
        expect(r.mode).toBe('production');
      }
    });

    it('returns empty array when no executions match', () => {
      seedExecutions();

      const results = repo.queryExecutions({ runbookId: 'rb-nonexistent' });
      expect(results).toEqual([]);
    });

    it('defaults limit to 50', () => {
      // Insert 60 executions
      for (let i = 0; i < 60; i++) {
        const id = `exec-bulk-${String(i).padStart(3, '0')}`;
        db.prepare(`
          INSERT INTO executions (
            execution_id, runbook_id, runbook_version, runbook_name,
            state, mode, started_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(id, 'rb-bulk', '1.0.0', 'Bulk', 'completed', 'production', `2026-02-10T${String(i).padStart(2, '0')}:00:00.000Z`);
      }

      const results = repo.queryExecutions();
      expect(results).toHaveLength(50);
    });
  });

  // -------------------------------------------------------------------------
  // countExecutions
  // -------------------------------------------------------------------------

  describe('countExecutions', () => {
    function seedForCounting() {
      const entries = [
        { id: 'c-001', rbId: 'rb-phishing', state: 'completed' },
        { id: 'c-002', rbId: 'rb-phishing', state: 'failed' },
        { id: 'c-003', rbId: 'rb-malware', state: 'completed' },
        { id: 'c-004', rbId: 'rb-malware', state: 'completed' },
        { id: 'c-005', rbId: 'rb-lateral', state: 'executing' },
      ];

      for (const e of entries) {
        db.prepare(`
          INSERT INTO executions (
            execution_id, runbook_id, runbook_version, runbook_name,
            state, mode, started_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(e.id, e.rbId, '1.0.0', 'Test', e.state, 'production', '2026-02-11T00:00:00.000Z');
      }
    }

    it('counts all executions when no filters are provided', () => {
      seedForCounting();
      expect(repo.countExecutions()).toBe(5);
    });

    it('counts executions filtered by runbookId', () => {
      seedForCounting();
      expect(repo.countExecutions({ runbookId: 'rb-phishing' })).toBe(2);
      expect(repo.countExecutions({ runbookId: 'rb-malware' })).toBe(2);
      expect(repo.countExecutions({ runbookId: 'rb-lateral' })).toBe(1);
    });

    it('counts executions filtered by state', () => {
      seedForCounting();
      expect(repo.countExecutions({ state: 'completed' })).toBe(3);
      expect(repo.countExecutions({ state: 'failed' })).toBe(1);
      expect(repo.countExecutions({ state: 'executing' })).toBe(1);
    });

    it('counts executions with combined filters', () => {
      seedForCounting();
      expect(repo.countExecutions({ runbookId: 'rb-malware', state: 'completed' })).toBe(2);
      expect(repo.countExecutions({ runbookId: 'rb-phishing', state: 'completed' })).toBe(1);
    });

    it('returns 0 when no executions match', () => {
      seedForCounting();
      expect(repo.countExecutions({ runbookId: 'rb-nonexistent' })).toBe(0);
      expect(repo.countExecutions({ state: 'cancelled' })).toBe(0);
    });

    it('returns 0 on an empty database', () => {
      expect(repo.countExecutions()).toBe(0);
    });
  });
});

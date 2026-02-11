import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'crypto';
import { initDatabase, closeDatabase } from '../../../src/db/index.ts';
import { AuditLogger } from '../../../src/engine/audit-logger.ts';
import type { AuditEntry } from '../../../src/engine/audit-logger.ts';
import type Database from 'better-sqlite3';

/**
 * Helper: insert a minimal execution row so that the audit_log foreign key is satisfied.
 */
function insertExecution(db: Database.Database, executionId: string, runbookId: string): void {
  db.prepare(`
    INSERT INTO executions (execution_id, runbook_id, runbook_version, runbook_name, state, mode, started_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(executionId, runbookId, '1.0', 'Test Runbook', 'idle', 'production', new Date().toISOString());
}

/**
 * Recompute the expected hash for an audit entry to verify chain integrity.
 */
function expectedHash(
  prevHash: string | null,
  eventType: string,
  executionId: string,
  details: string,
  timestamp: string,
): string {
  const payload = `${prevHash ?? ''}|${eventType}|${executionId}|${details}|${timestamp}`;
  return createHash('sha256').update(payload).digest('hex');
}

describe('AuditLogger', () => {
  let db: Database.Database;
  let logger: AuditLogger;

  const EXEC_ID = 'exec-test-001';
  const RUNBOOK_ID = 'rb-phishing-001';

  beforeEach(() => {
    db = initDatabase({ path: ':memory:', inMemory: true });
    insertExecution(db, EXEC_ID, RUNBOOK_ID);
    logger = new AuditLogger(db);
  });

  afterEach(() => {
    closeDatabase();
  });

  // -----------------------------------------------------------------------
  // Execution events
  // -----------------------------------------------------------------------

  describe('execution events', () => {
    it('logs execution_started with default actor', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.execution_id).toBe(EXEC_ID);
      expect(entry.runbook_id).toBe(RUNBOOK_ID);
      expect(entry.event_type).toBe('execution_started');
      expect(entry.actor).toBe('system');
      expect(entry.prev_hash).toBeNull();
      expect(entry.hash).toBeTruthy();
      expect(entry.created_at).toBeTruthy();
    });

    it('logs execution_started with custom actor and details', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID, 'analyst@corp.com', {
        trigger: 'manual',
        alert_id: 'alert-42',
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.actor).toBe('analyst@corp.com');
      expect(entry.details).toEqual({
        trigger: 'manual',
        alert_id: 'alert-42',
      });
    });

    it('logs execution_completed', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID, { steps_run: 5 });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const completed = entries[1]!;
      expect(completed.event_type).toBe('execution_completed');
      expect(completed.details).toEqual({ steps_run: 5 });
    });

    it('logs execution_failed with error', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logExecutionFailed(EXEC_ID, RUNBOOK_ID, 'Timeout after 300s', {
        step_id: 'step-03',
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const failed = entries[1]!;
      expect(failed.event_type).toBe('execution_failed');
      expect(failed.details).toEqual({
        error: 'Timeout after 300s',
        step_id: 'step-03',
      });
    });
  });

  // -----------------------------------------------------------------------
  // Step events
  // -----------------------------------------------------------------------

  describe('step events', () => {
    it('logs step_started', () => {
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'isolate_host');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('step_started');
      expect(entry.details).toEqual({
        step_id: 'step-01',
        action: 'isolate_host',
      });
    });

    it('logs step_completed with duration', () => {
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem', 1234);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const completed = entries[1]!;
      expect(completed.event_type).toBe('step_completed');
      expect(completed.details).toEqual({
        step_id: 'step-01',
        action: 'query_siem',
        duration_ms: 1234,
      });
    });

    it('logs step_failed with error', () => {
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-02', 'block_ip');
      logger.logStepFailed(EXEC_ID, RUNBOOK_ID, 'step-02', 'Firewall adapter unreachable');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const failed = entries[1]!;
      expect(failed.event_type).toBe('step_failed');
      expect(failed.details).toEqual({
        step_id: 'step-02',
        error: 'Firewall adapter unreachable',
      });
    });
  });

  // -----------------------------------------------------------------------
  // Approval events
  // -----------------------------------------------------------------------

  describe('approval events', () => {
    it('logs approval_requested', () => {
      logger.logApprovalRequested(EXEC_ID, RUNBOOK_ID, 'step-03', {
        action: 'isolate_host',
        target: '10.0.0.5',
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('approval_requested');
      expect(entry.details).toEqual({
        step_id: 'step-03',
        action: 'isolate_host',
        target: '10.0.0.5',
      });
    });

    it('logs approval_requested with no extra details', () => {
      logger.logApprovalRequested(EXEC_ID, RUNBOOK_ID, 'step-03');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.details).toEqual({ step_id: 'step-03' });
    });

    it('logs approval_granted with approver as actor', () => {
      logger.logApprovalGranted(EXEC_ID, RUNBOOK_ID, 'step-03', 'manager@corp.com');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('approval_granted');
      expect(entry.actor).toBe('manager@corp.com');
      expect(entry.details).toEqual({
        step_id: 'step-03',
        approver: 'manager@corp.com',
      });
    });

    it('logs approval_denied with reason', () => {
      logger.logApprovalDenied(EXEC_ID, RUNBOOK_ID, 'step-03', 'Risk too high');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('approval_denied');
      expect(entry.details).toEqual({
        step_id: 'step-03',
        reason: 'Risk too high',
      });
    });

    it('logs approval_denied without reason', () => {
      logger.logApprovalDenied(EXEC_ID, RUNBOOK_ID, 'step-03');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('approval_denied');
      // reason key should be absent, not null
      expect(entry.details).toEqual({ step_id: 'step-03' });
      expect('reason' in entry.details).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // State change events
  // -----------------------------------------------------------------------

  describe('state change events', () => {
    it('logs state_changed with from and to states', () => {
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'idle', 'validating');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('state_changed');
      expect(entry.details).toEqual({
        from_state: 'idle',
        to_state: 'validating',
      });
    });

    it('logs multiple state transitions in sequence', () => {
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'idle', 'validating');
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'validating', 'planning');
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'planning', 'executing');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(3);

      expect(entries[0]!.details).toEqual({ from_state: 'idle', to_state: 'validating' });
      expect(entries[1]!.details).toEqual({ from_state: 'validating', to_state: 'planning' });
      expect(entries[2]!.details).toEqual({ from_state: 'planning', to_state: 'executing' });
    });
  });

  // -----------------------------------------------------------------------
  // Rollback events
  // -----------------------------------------------------------------------

  describe('rollback events', () => {
    it('logs rollback_started', () => {
      logger.logRollbackStarted(EXEC_ID, RUNBOOK_ID, { reason: 'step-03 failed' });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.event_type).toBe('rollback_started');
      expect(entry.details).toEqual({ reason: 'step-03 failed' });
    });

    it('logs rollback_started with no extra details', () => {
      logger.logRollbackStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.details).toEqual({});
    });

    it('logs rollback_completed', () => {
      logger.logRollbackStarted(EXEC_ID, RUNBOOK_ID);
      logger.logRollbackCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const completed = entries[1]!;
      expect(completed.event_type).toBe('rollback_completed');
      expect(completed.details).toEqual({});
    });

    it('logs rollback_failed with error', () => {
      logger.logRollbackStarted(EXEC_ID, RUNBOOK_ID);
      logger.logRollbackFailed(EXEC_ID, RUNBOOK_ID, 'Adapter timeout during undo');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);

      const failed = entries[1]!;
      expect(failed.event_type).toBe('rollback_failed');
      expect(failed.details).toEqual({ error: 'Adapter timeout during undo' });
    });
  });

  // -----------------------------------------------------------------------
  // Chain integrity
  // -----------------------------------------------------------------------

  describe('chain integrity', () => {
    it('first entry has prev_hash = null', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.prev_hash).toBeNull();
    });

    it('second entry references first entry hash as prev_hash', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);
      expect(entries[1]!.prev_hash).toBe(entries[0]!.hash);
    });

    it('builds a valid hash chain across multiple entries', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem', 500);
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(4);

      // Verify the chain: each entry's prev_hash must equal the prior entry's hash
      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]!.prev_hash).toBe(entries[i - 1]!.hash);
      }
    });

    it('computes hashes correctly using SHA-256', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      const entry = entries[0]!;

      // Recompute the hash and verify
      const detailsJson = JSON.stringify(entry.details);
      const recomputed = expectedHash(
        entry.prev_hash,
        entry.event_type,
        entry.execution_id,
        detailsJson,
        entry.created_at,
      );
      expect(entry.hash).toBe(recomputed);
    });

    it('each hash in a chain is independently verifiable', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'isolate_host');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'isolate_host', 800);

      const entries = logger.getExecutionLog(EXEC_ID);

      for (const entry of entries) {
        const detailsJson = JSON.stringify(entry.details);
        const recomputed = expectedHash(
          entry.prev_hash,
          entry.event_type,
          entry.execution_id,
          detailsJson,
          entry.created_at,
        );
        expect(entry.hash).toBe(recomputed);
      }
    });

    it('separate executions have independent chains', () => {
      const EXEC_ID_2 = 'exec-test-002';
      insertExecution(db, EXEC_ID_2, RUNBOOK_ID);

      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logExecutionStarted(EXEC_ID_2, RUNBOOK_ID);

      const chain1 = logger.getExecutionLog(EXEC_ID);
      const chain2 = logger.getExecutionLog(EXEC_ID_2);

      // Both first entries should have null prev_hash (independent chains)
      expect(chain1[0]!.prev_hash).toBeNull();
      expect(chain2[0]!.prev_hash).toBeNull();

      // Hashes should differ (different execution IDs, likely different timestamps)
      expect(chain1[0]!.hash).not.toBe(chain2[0]!.hash);
    });
  });

  // -----------------------------------------------------------------------
  // Query: getExecutionLog
  // -----------------------------------------------------------------------

  describe('getExecutionLog', () => {
    it('returns empty array for unknown execution', () => {
      const entries = logger.getExecutionLog('exec-nonexistent');
      expect(entries).toEqual([]);
    });

    it('returns entries in insertion order', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'collect_logs');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'collect_logs', 200);
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(4);

      const types = entries.map((e) => e.event_type);
      expect(types).toEqual([
        'execution_started',
        'step_started',
        'step_completed',
        'execution_completed',
      ]);
    });

    it('only returns entries for the requested execution', () => {
      const EXEC_ID_2 = 'exec-test-002';
      insertExecution(db, EXEC_ID_2, RUNBOOK_ID);

      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logExecutionStarted(EXEC_ID_2, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_ip');
      logger.logStepStarted(EXEC_ID_2, RUNBOOK_ID, 'step-01', 'isolate_host');

      const entries1 = logger.getExecutionLog(EXEC_ID);
      const entries2 = logger.getExecutionLog(EXEC_ID_2);

      expect(entries1).toHaveLength(2);
      expect(entries2).toHaveLength(2);

      expect(entries1.every((e) => e.execution_id === EXEC_ID)).toBe(true);
      expect(entries2.every((e) => e.execution_id === EXEC_ID_2)).toBe(true);
    });

    it('parses details JSON correctly', () => {
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'enrich_ioc', 750);

      const entries = logger.getExecutionLog(EXEC_ID);
      const entry = entries[0]!;

      expect(typeof entry.details).toBe('object');
      expect(entry.details).toEqual({
        step_id: 'step-01',
        action: 'enrich_ioc',
        duration_ms: 750,
      });
    });

    it('returns proper AuditEntry shape', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      const entry = entries[0]!;

      // Verify the shape matches AuditEntry
      expect(entry).toHaveProperty('id');
      expect(entry).toHaveProperty('execution_id');
      expect(entry).toHaveProperty('runbook_id');
      expect(entry).toHaveProperty('event_type');
      expect(entry).toHaveProperty('actor');
      expect(entry).toHaveProperty('details');
      expect(entry).toHaveProperty('prev_hash');
      expect(entry).toHaveProperty('hash');
      expect(entry).toHaveProperty('created_at');

      // Verify types
      expect(typeof entry.id).toBe('string');
      expect(typeof entry.execution_id).toBe('string');
      expect(typeof entry.runbook_id).toBe('string');
      expect(typeof entry.event_type).toBe('string');
      expect(typeof entry.actor).toBe('string');
      expect(typeof entry.details).toBe('object');
      expect(typeof entry.hash).toBe('string');
      expect(typeof entry.created_at).toBe('string');
    });
  });

  // -----------------------------------------------------------------------
  // Export to JSON
  // -----------------------------------------------------------------------

  describe('exportToJson', () => {
    it('exports valid JSON string', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID);

      const json = logger.exportToJson(EXEC_ID);
      expect(() => JSON.parse(json)).not.toThrow();
    });

    it('exported JSON matches getExecutionLog output', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_domain');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_domain', 1500);
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      const json = logger.exportToJson(EXEC_ID);
      const parsed = JSON.parse(json) as AuditEntry[];

      expect(parsed).toEqual(entries);
    });

    it('exports empty array for unknown execution', () => {
      const json = logger.exportToJson('exec-nonexistent');
      const parsed = JSON.parse(json) as AuditEntry[];
      expect(parsed).toEqual([]);
    });

    it('exported JSON is pretty-printed', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const json = logger.exportToJson(EXEC_ID);
      // Pretty-printed JSON has newlines and indentation
      expect(json).toContain('\n');
      expect(json).toContain('  ');
    });
  });

  // -----------------------------------------------------------------------
  // Append-only guarantee
  // -----------------------------------------------------------------------

  describe('append-only behavior', () => {
    it('each entry gets a unique id', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'collect_logs');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'collect_logs', 100);

      const entries = logger.getExecutionLog(EXEC_ID);
      const ids = entries.map((e) => e.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(ids.length);
    });

    it('entries are immutable after insertion', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);

      const before = logger.getExecutionLog(EXEC_ID);
      const entryBefore = before[0]!;

      // Log more entries
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_ip');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_ip', 300);

      const after = logger.getExecutionLog(EXEC_ID);
      const entryAfter = after[0]!;

      // Original entry should be unchanged
      expect(entryAfter.id).toBe(entryBefore.id);
      expect(entryAfter.hash).toBe(entryBefore.hash);
      expect(entryAfter.created_at).toBe(entryBefore.created_at);
      expect(entryAfter.details).toEqual(entryBefore.details);
    });
  });

  // -----------------------------------------------------------------------
  // Full lifecycle scenario
  // -----------------------------------------------------------------------

  describe('full lifecycle scenario', () => {
    it('records a complete execution lifecycle with valid chain', () => {
      // Start
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID, 'soc-analyst');
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'idle', 'validating');
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'validating', 'executing');

      // Step 1 succeeds
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem', 500);

      // Step 2 needs approval
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host');
      logger.logApprovalRequested(EXEC_ID, RUNBOOK_ID, 'step-02');
      logger.logApprovalGranted(EXEC_ID, RUNBOOK_ID, 'step-02', 'team-lead@corp.com');
      logger.logStepCompleted(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host', 2000);

      // Step 3 fails, triggering rollback
      logger.logStepStarted(EXEC_ID, RUNBOOK_ID, 'step-03', 'block_ip');
      logger.logStepFailed(EXEC_ID, RUNBOOK_ID, 'step-03', 'Connection refused');
      logger.logRollbackStarted(EXEC_ID, RUNBOOK_ID, { trigger: 'step-03 failure' });
      logger.logRollbackCompleted(EXEC_ID, RUNBOOK_ID);
      logger.logStateChanged(EXEC_ID, RUNBOOK_ID, 'executing', 'failed');
      logger.logExecutionFailed(EXEC_ID, RUNBOOK_ID, 'Step step-03 failed');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(15);

      // Verify complete chain integrity
      expect(entries[0]!.prev_hash).toBeNull();
      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]!.prev_hash).toBe(entries[i - 1]!.hash);
      }

      // Verify every hash is independently valid
      for (const entry of entries) {
        const detailsJson = JSON.stringify(entry.details);
        const recomputed = expectedHash(
          entry.prev_hash,
          entry.event_type,
          entry.execution_id,
          detailsJson,
          entry.created_at,
        );
        expect(entry.hash).toBe(recomputed);
      }

      // Verify event type sequence
      const types = entries.map((e) => e.event_type);
      expect(types).toEqual([
        'execution_started',
        'state_changed',
        'state_changed',
        'step_started',
        'step_completed',
        'step_started',
        'approval_requested',
        'approval_granted',
        'step_completed',
        'step_started',
        'step_failed',
        'rollback_started',
        'rollback_completed',
        'state_changed',
        'execution_failed',
      ]);
    });
  });
});

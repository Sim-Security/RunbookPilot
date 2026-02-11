import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'crypto';
import { initDatabase, closeDatabase } from '../../../src/db/index.ts';
import { AuditLogger } from '../../../src/engine/audit-logger.ts';
import type Database from 'better-sqlite3';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

/**
 * Insert a minimal execution row to satisfy the audit_log foreign key.
 */
function insertExecution(db: Database.Database, executionId: string, runbookId: string): void {
  db.prepare(`
    INSERT INTO executions (execution_id, runbook_id, runbook_version, runbook_name, state, mode, started_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(executionId, runbookId, '1.0', 'Test Runbook', 'executing', 'simulation', new Date().toISOString());
}

/**
 * Recompute the expected SHA-256 hash to verify chain integrity.
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

// ---------------------------------------------------------------------------
// Tests: Simulation Audit Events (L2)
// ---------------------------------------------------------------------------

describe('AuditLogger — Simulation Events', () => {
  let db: Database.Database;
  let logger: AuditLogger;

  const EXEC_ID = 'exec-sim-001';
  const RUNBOOK_ID = 'rb-sim-test-001';

  beforeEach(() => {
    db = initDatabase({ path: ':memory:', inMemory: true });
    insertExecution(db, EXEC_ID, RUNBOOK_ID);
    logger = new AuditLogger(db);
  });

  afterEach(() => {
    closeDatabase();
  });

  // -----------------------------------------------------------------------
  // logSimulationStarted
  // -----------------------------------------------------------------------

  describe('logSimulationStarted', () => {
    it('writes correct event_type', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.event_type).toBe('simulation_started');
    });

    it('writes system as default actor', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.actor).toBe('system');
    });

    it('writes correct execution_id and runbook_id', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.execution_id).toBe(EXEC_ID);
      expect(entries[0]!.runbook_id).toBe(RUNBOOK_ID);
    });

    it('includes optional details when provided', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID, {
        automation_level: 'L2',
        steps_count: 5,
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.details).toEqual({
        automation_level: 'L2',
        steps_count: 5,
      });
    });

    it('writes empty details when none provided', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.details).toEqual({});
    });

    it('first entry has prev_hash = null', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.prev_hash).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // logSimulationCompleted
  // -----------------------------------------------------------------------

  describe('logSimulationCompleted', () => {
    it('writes correct event_type', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);
      expect(entries[1]!.event_type).toBe('simulation_completed');
    });

    it('includes optional details', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID, {
        overall_confidence: 0.85,
        steps_simulated: 5,
        duration_ms: 1234,
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[1]!.details).toEqual({
        overall_confidence: 0.85,
        steps_simulated: 5,
        duration_ms: 1234,
      });
    });

    it('writes system as actor', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[1]!.actor).toBe('system');
    });
  });

  // -----------------------------------------------------------------------
  // logSimulationFailed
  // -----------------------------------------------------------------------

  describe('logSimulationFailed', () => {
    it('includes error in details', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationFailed(EXEC_ID, RUNBOOK_ID, 'Adapter timeout during simulation');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);
      expect(entries[1]!.event_type).toBe('simulation_failed');
      expect(entries[1]!.details).toHaveProperty('error', 'Adapter timeout during simulation');
    });

    it('includes optional extra details', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationFailed(EXEC_ID, RUNBOOK_ID, 'Step validation failed', {
        step_id: 'step-03',
        action: 'isolate_host',
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[1]!.details).toEqual({
        error: 'Step validation failed',
        step_id: 'step-03',
        action: 'isolate_host',
      });
    });

    it('is recorded as a failure (success=0 in DB)', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationFailed(EXEC_ID, RUNBOOK_ID, 'Failed');

      // Verify by querying raw DB for success column
      const row = db
        .prepare("SELECT success FROM audit_log WHERE event_type = 'simulation_failed'")
        .get() as { success: number };

      expect(row.success).toBe(0);
    });

    it('simulation_started is recorded as success (success=1)', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const row = db
        .prepare("SELECT success FROM audit_log WHERE event_type = 'simulation_started'")
        .get() as { success: number };

      expect(row.success).toBe(1);
    });

    it('simulation_completed is recorded as success (success=1)', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

      const row = db
        .prepare("SELECT success FROM audit_log WHERE event_type = 'simulation_completed'")
        .get() as { success: number };

      expect(row.success).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // logStepSimulated
  // -----------------------------------------------------------------------

  describe('logStepSimulated', () => {
    it('includes step_id and action in details', () => {
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.event_type).toBe('step_simulated');
      expect(entries[0]!.details).toHaveProperty('step_id', 'step-02');
      expect(entries[0]!.details).toHaveProperty('action', 'isolate_host');
    });

    it('includes optional extra details', () => {
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-02', 'block_ip', {
        confidence: 0.85,
        risk_score: 6,
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.details).toEqual({
        step_id: 'step-02',
        action: 'block_ip',
        confidence: 0.85,
        risk_score: 6,
      });
    });

    it('writes system as actor', () => {
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.actor).toBe('system');
    });

    it('is recorded as success (success=1)', () => {
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');

      const row = db
        .prepare("SELECT success FROM audit_log WHERE event_type = 'step_simulated'")
        .get() as { success: number };

      expect(row.success).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // logApprovalQueueCreated
  // -----------------------------------------------------------------------

  describe('logApprovalQueueCreated', () => {
    it('includes request_id in details', () => {
      logger.logApprovalQueueCreated(EXEC_ID, RUNBOOK_ID, 'req-abc-123');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.event_type).toBe('approval_queue_created');
      expect(entries[0]!.details).toHaveProperty('request_id', 'req-abc-123');
    });

    it('includes optional extra details', () => {
      logger.logApprovalQueueCreated(EXEC_ID, RUNBOOK_ID, 'req-abc-123', {
        step_id: 'step-03',
        action: 'isolate_host',
        expires_in_seconds: 3600,
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.details).toEqual({
        request_id: 'req-abc-123',
        step_id: 'step-03',
        action: 'isolate_host',
        expires_in_seconds: 3600,
      });
    });

    it('writes system as actor', () => {
      logger.logApprovalQueueCreated(EXEC_ID, RUNBOOK_ID, 'req-abc-123');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.actor).toBe('system');
    });
  });

  // -----------------------------------------------------------------------
  // logApprovalQueueExecuted
  // -----------------------------------------------------------------------

  describe('logApprovalQueueExecuted', () => {
    it('includes request_id in details', () => {
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-abc-123', 'admin@corp.com');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.event_type).toBe('approval_queue_executed');
      expect(entries[0]!.details).toHaveProperty('request_id', 'req-abc-123');
    });

    it('uses approver as actor', () => {
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-abc-123', 'manager@corp.com');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.actor).toBe('manager@corp.com');
    });

    it('includes optional extra details', () => {
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-abc-123', 'admin@corp.com', {
        step_id: 'step-03',
        action: 'isolate_host',
        execution_mode: 'production',
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.details).toEqual({
        request_id: 'req-abc-123',
        step_id: 'step-03',
        action: 'isolate_host',
        execution_mode: 'production',
      });
    });

    it('is recorded as success (success=1)', () => {
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-001', 'admin@corp.com');

      const row = db
        .prepare("SELECT success FROM audit_log WHERE event_type = 'approval_queue_executed'")
        .get() as { success: number };

      expect(row.success).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // Hash chain integrity — simulation events
  // -----------------------------------------------------------------------

  describe('hash chain integrity across simulation events', () => {
    it('first simulation event has prev_hash = null', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries[0]!.prev_hash).toBeNull();
    });

    it('second event references first event hash as prev_hash', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(2);
      expect(entries[1]!.prev_hash).toBe(entries[0]!.hash);
    });

    it('builds a valid chain across a full simulation lifecycle', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID, { level: 'L2' });
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host');
      logger.logApprovalQueueCreated(EXEC_ID, RUNBOOK_ID, 'req-001');
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-001', 'admin@corp.com');
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID, { confidence: 0.85 });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(6);

      // Verify the chain: each entry's prev_hash equals the prior entry's hash
      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]!.prev_hash).toBe(entries[i - 1]!.hash);
      }
    });

    it('each hash in the chain is independently verifiable', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'block_ip');
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host');
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

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

    it('simulation failed event is in the chain correctly', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logSimulationFailed(EXEC_ID, RUNBOOK_ID, 'Adapter unreachable');

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(3);

      // Verify chain
      expect(entries[0]!.prev_hash).toBeNull();
      expect(entries[1]!.prev_hash).toBe(entries[0]!.hash);
      expect(entries[2]!.prev_hash).toBe(entries[1]!.hash);

      // Verify hashes are correct
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

    it('mixing simulation and regular events maintains chain integrity', () => {
      logger.logExecutionStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);
      logger.logExecutionCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(5);

      // Verify the chain
      expect(entries[0]!.prev_hash).toBeNull();
      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]!.prev_hash).toBe(entries[i - 1]!.hash);
      }

      // Verify event type sequence
      const types = entries.map((e) => e.event_type);
      expect(types).toEqual([
        'execution_started',
        'simulation_started',
        'step_simulated',
        'simulation_completed',
        'execution_completed',
      ]);
    });

    it('separate executions have independent chains', () => {
      const EXEC_ID_2 = 'exec-sim-002';
      insertExecution(db, EXEC_ID_2, RUNBOOK_ID);

      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationStarted(EXEC_ID_2, RUNBOOK_ID);

      const chain1 = logger.getExecutionLog(EXEC_ID);
      const chain2 = logger.getExecutionLog(EXEC_ID_2);

      expect(chain1[0]!.prev_hash).toBeNull();
      expect(chain2[0]!.prev_hash).toBeNull();

      // Hashes differ because execution IDs differ
      expect(chain1[0]!.hash).not.toBe(chain2[0]!.hash);
    });
  });

  // -----------------------------------------------------------------------
  // Full simulation lifecycle
  // -----------------------------------------------------------------------

  describe('full simulation lifecycle scenario', () => {
    it('records a complete simulation lifecycle with valid chain', () => {
      // Start simulation
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID, {
        automation_level: 'L2',
        mode: 'simulation',
      });

      // Simulate steps
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem', {
        confidence: 0.9,
      });
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-02', 'isolate_host', {
        confidence: 0.75,
        risk_score: 8,
      });
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-03', 'block_ip', {
        confidence: 0.8,
        risk_score: 6,
      });

      // Create approval queue entry
      logger.logApprovalQueueCreated(EXEC_ID, RUNBOOK_ID, 'req-001', {
        step_id: 'step-02',
        action: 'isolate_host',
      });

      // Execute from approval queue
      logger.logApprovalQueueExecuted(EXEC_ID, RUNBOOK_ID, 'req-001', 'soc-lead@corp.com', {
        step_id: 'step-02',
      });

      // Complete simulation
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID, {
        overall_confidence: 0.82,
        steps_simulated: 3,
        duration_ms: 5432,
      });

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(7);

      // Verify event type sequence
      const types = entries.map((e) => e.event_type);
      expect(types).toEqual([
        'simulation_started',
        'step_simulated',
        'step_simulated',
        'step_simulated',
        'approval_queue_created',
        'approval_queue_executed',
        'simulation_completed',
      ]);

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

      // Verify approval_queue_executed has the approver as actor
      const approvalExecuted = entries.find((e) => e.event_type === 'approval_queue_executed');
      expect(approvalExecuted!.actor).toBe('soc-lead@corp.com');

      // All other events should have 'system' as actor
      for (const entry of entries) {
        if (entry.event_type !== 'approval_queue_executed') {
          expect(entry.actor).toBe('system');
        }
      }
    });
  });

  // -----------------------------------------------------------------------
  // getExecutionLog for simulation events
  // -----------------------------------------------------------------------

  describe('getExecutionLog for simulation events', () => {
    it('returns entries in insertion order', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'collect_logs');
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      expect(entries).toHaveLength(3);

      const types = entries.map((e) => e.event_type);
      expect(types).toEqual([
        'simulation_started',
        'step_simulated',
        'simulation_completed',
      ]);
    });

    it('each entry gets a unique id', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logStepSimulated(EXEC_ID, RUNBOOK_ID, 'step-01', 'query_siem');
      logger.logSimulationCompleted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      const ids = entries.map((e) => e.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(ids.length);
    });

    it('returns proper AuditEntry shape for simulation events', () => {
      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);

      const entries = logger.getExecutionLog(EXEC_ID);
      const entry = entries[0]!;

      expect(entry).toHaveProperty('id');
      expect(entry).toHaveProperty('execution_id');
      expect(entry).toHaveProperty('runbook_id');
      expect(entry).toHaveProperty('event_type');
      expect(entry).toHaveProperty('actor');
      expect(entry).toHaveProperty('details');
      expect(entry).toHaveProperty('prev_hash');
      expect(entry).toHaveProperty('hash');
      expect(entry).toHaveProperty('created_at');

      expect(typeof entry.id).toBe('string');
      expect(typeof entry.hash).toBe('string');
      expect(typeof entry.details).toBe('object');
      expect(typeof entry.created_at).toBe('string');
    });

    it('only returns entries for the requested execution', () => {
      const EXEC_ID_2 = 'exec-sim-002';
      insertExecution(db, EXEC_ID_2, RUNBOOK_ID);

      logger.logSimulationStarted(EXEC_ID, RUNBOOK_ID);
      logger.logSimulationStarted(EXEC_ID_2, RUNBOOK_ID);

      const entries1 = logger.getExecutionLog(EXEC_ID);
      const entries2 = logger.getExecutionLog(EXEC_ID_2);

      expect(entries1).toHaveLength(1);
      expect(entries2).toHaveLength(1);
      expect(entries1[0]!.execution_id).toBe(EXEC_ID);
      expect(entries2[0]!.execution_id).toBe(EXEC_ID_2);
    });
  });
});

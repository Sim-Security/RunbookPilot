/**
 * RunbookPilot Audit Logger
 *
 * Append-only, hash-chained audit log for SOC runbook executions.
 * Each entry's hash is computed from (prev_hash + event_type + execution_id + details + timestamp),
 * creating a tamper-evident chain per execution.
 *
 * Only INSERTs are performed -- never UPDATE or DELETE.
 *
 * @module engine/audit-logger
 */

import { createHash, randomUUID } from 'crypto';
import type Database from 'better-sqlite3';
import type { AuditLogEntry, ExecutionState, StepAction } from '../types/playbook.ts';

// Re-export playbook types used by consumers of this module.
export type { AuditLogEntry, ExecutionState, StepAction };

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Event types that can be recorded in the audit log.
 */
export type AuditEventType =
  | 'execution_started'
  | 'execution_completed'
  | 'execution_failed'
  | 'step_started'
  | 'step_completed'
  | 'step_failed'
  | 'approval_requested'
  | 'approval_granted'
  | 'approval_denied'
  | 'approval_expired'
  | 'rollback_started'
  | 'rollback_completed'
  | 'rollback_failed'
  | 'state_changed'
  // L2 simulation events
  | 'simulation_started'
  | 'simulation_completed'
  | 'simulation_failed'
  | 'step_simulated'
  | 'approval_queue_created'
  | 'approval_queue_executed';

/**
 * Represents a row returned from the audit_log table.
 */
export interface AuditEntry {
  id: string;
  execution_id: string;
  runbook_id: string;
  event_type: string;
  actor: string;
  details: Record<string, unknown>;
  prev_hash: string | null;
  hash: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Raw row shape returned by better-sqlite3 before we parse the `details` JSON.
 */
interface AuditRowRaw {
  id: string;
  execution_id: string;
  runbook_id: string;
  event_type: string;
  actor: string;
  details: string;
  success: number;
  prev_hash: string | null;
  hash: string;
  timestamp: string;
}

/**
 * Compute a SHA-256 hash over the chain-relevant fields of an audit entry.
 */
function computeHash(
  prevHash: string | null,
  eventType: string,
  executionId: string,
  details: string,
  timestamp: string,
): string {
  const payload = `${prevHash ?? ''}|${eventType}|${executionId}|${details}|${timestamp}`;
  return createHash('sha256').update(payload).digest('hex');
}

/**
 * Get current ISO-8601 timestamp with millisecond precision.
 */
function nowISO(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// AuditLogger class
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly insertStmt: Database.Statement;
  private readonly selectLastHashStmt: Database.Statement;
  private readonly selectByExecutionStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.insertStmt = db.prepare(`
      INSERT INTO audit_log (id, timestamp, execution_id, runbook_id, event_type, actor, details, success, prev_hash, hash)
      VALUES (@id, @timestamp, @execution_id, @runbook_id, @event_type, @actor, @details, @success, @prev_hash, @hash)
    `);

    this.selectLastHashStmt = db.prepare(`
      SELECT hash FROM audit_log
      WHERE execution_id = ?
      ORDER BY rowid DESC
      LIMIT 1
    `);

    this.selectByExecutionStmt = db.prepare(`
      SELECT * FROM audit_log
      WHERE execution_id = ?
      ORDER BY rowid ASC
    `);
  }

  // -----------------------------------------------------------------------
  // Execution events
  // -----------------------------------------------------------------------

  logExecutionStarted(
    executionId: string,
    runbookId: string,
    actor?: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'execution_started', actor ?? 'system', {
      ...details,
    });
  }

  logExecutionCompleted(
    executionId: string,
    runbookId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'execution_completed', 'system', {
      ...details,
    });
  }

  logExecutionFailed(
    executionId: string,
    runbookId: string,
    error: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'execution_failed', 'system', {
      error,
      ...details,
    });
  }

  // -----------------------------------------------------------------------
  // Step events
  // -----------------------------------------------------------------------

  logStepStarted(
    executionId: string,
    runbookId: string,
    stepId: string,
    action: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'step_started', 'system', {
      step_id: stepId,
      action,
    });
  }

  logStepCompleted(
    executionId: string,
    runbookId: string,
    stepId: string,
    action: string,
    durationMs: number,
  ): void {
    this.writeEntry(executionId, runbookId, 'step_completed', 'system', {
      step_id: stepId,
      action,
      duration_ms: durationMs,
    });
  }

  logStepFailed(
    executionId: string,
    runbookId: string,
    stepId: string,
    error: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'step_failed', 'system', {
      step_id: stepId,
      error,
    });
  }

  // -----------------------------------------------------------------------
  // Approval events
  // -----------------------------------------------------------------------

  logApprovalRequested(
    executionId: string,
    runbookId: string,
    stepId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'approval_requested', 'system', {
      step_id: stepId,
      ...details,
    });
  }

  logApprovalGranted(
    executionId: string,
    runbookId: string,
    stepId: string,
    approver: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'approval_granted', approver, {
      step_id: stepId,
      approver,
    });
  }

  logApprovalDenied(
    executionId: string,
    runbookId: string,
    stepId: string,
    reason?: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'approval_denied', 'system', {
      step_id: stepId,
      ...(reason !== undefined ? { reason } : {}),
    });
  }

  // -----------------------------------------------------------------------
  // State change events
  // -----------------------------------------------------------------------

  logStateChanged(
    executionId: string,
    runbookId: string,
    fromState: string,
    toState: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'state_changed', 'system', {
      from_state: fromState,
      to_state: toState,
    });
  }

  // -----------------------------------------------------------------------
  // Rollback events
  // -----------------------------------------------------------------------

  logRollbackStarted(
    executionId: string,
    runbookId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'rollback_started', 'system', {
      ...details,
    });
  }

  logRollbackCompleted(executionId: string, runbookId: string): void {
    this.writeEntry(executionId, runbookId, 'rollback_completed', 'system', {});
  }

  logRollbackFailed(
    executionId: string,
    runbookId: string,
    error: string,
  ): void {
    this.writeEntry(executionId, runbookId, 'rollback_failed', 'system', {
      error,
    });
  }

  // -----------------------------------------------------------------------
  // Simulation events (L2)
  // -----------------------------------------------------------------------

  logSimulationStarted(
    executionId: string,
    runbookId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'simulation_started', 'system', {
      ...details,
    });
  }

  logSimulationCompleted(
    executionId: string,
    runbookId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'simulation_completed', 'system', {
      ...details,
    });
  }

  logSimulationFailed(
    executionId: string,
    runbookId: string,
    error: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'simulation_failed', 'system', {
      error,
      ...details,
    });
  }

  logStepSimulated(
    executionId: string,
    runbookId: string,
    stepId: string,
    action: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'step_simulated', 'system', {
      step_id: stepId,
      action,
      ...details,
    });
  }

  logApprovalQueueCreated(
    executionId: string,
    runbookId: string,
    requestId: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'approval_queue_created', 'system', {
      request_id: requestId,
      ...details,
    });
  }

  logApprovalQueueExecuted(
    executionId: string,
    runbookId: string,
    requestId: string,
    approver: string,
    details?: Record<string, unknown>,
  ): void {
    this.writeEntry(executionId, runbookId, 'approval_queue_executed', approver, {
      request_id: requestId,
      ...details,
    });
  }

  // -----------------------------------------------------------------------
  // Query methods
  // -----------------------------------------------------------------------

  /**
   * Retrieve all audit entries for a given execution, ordered by insertion.
   */
  getExecutionLog(executionId: string): AuditEntry[] {
    const rows = this.selectByExecutionStmt.all(executionId) as AuditRowRaw[];
    return rows.map((row) => this.toAuditEntry(row));
  }

  /**
   * Export a full execution log as a JSON string (pretty-printed).
   */
  exportToJson(executionId: string): string {
    const entries = this.getExecutionLog(executionId);
    return JSON.stringify(entries, null, 2);
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  /**
   * Core append-only write method.
   * Computes the hash chain and inserts a single row.
   */
  private writeEntry(
    executionId: string,
    runbookId: string,
    eventType: AuditEventType,
    actor: string,
    details: Record<string, unknown>,
  ): void {
    const id = randomUUID();
    const timestamp = nowISO();
    const detailsJson = JSON.stringify(details);

    // Retrieve the previous hash in this execution's chain
    const lastRow = this.selectLastHashStmt.get(executionId) as
      | { hash: string }
      | undefined;
    const prevHash = lastRow?.hash ?? null;

    const hash = computeHash(prevHash, eventType, executionId, detailsJson, timestamp);

    // Determine success flag based on event type
    const isFailure = eventType.endsWith('_failed') || eventType === 'approval_denied';
    const success = isFailure ? 0 : 1;

    this.insertStmt.run({
      id,
      timestamp,
      execution_id: executionId,
      runbook_id: runbookId,
      event_type: eventType,
      actor,
      details: detailsJson,
      success,
      prev_hash: prevHash,
      hash,
    });
  }

  /**
   * Convert a raw database row into a typed AuditEntry.
   */
  private toAuditEntry(row: AuditRowRaw): AuditEntry {
    let parsedDetails: Record<string, unknown>;
    try {
      parsedDetails = JSON.parse(row.details) as Record<string, unknown>;
    } catch {
      parsedDetails = {};
    }

    return {
      id: row.id,
      execution_id: row.execution_id,
      runbook_id: row.runbook_id,
      event_type: row.event_type,
      actor: row.actor,
      details: parsedDetails,
      prev_hash: row.prev_hash,
      hash: row.hash,
      created_at: row.timestamp,
    };
  }
}

/**
 * Approval Queue Repository
 *
 * Persistence layer for L2 simulation approval queue entries.
 * Manages the lifecycle of approval requests: creation, listing,
 * approval, denial, and expiration.
 *
 * Uses SQLite via better-sqlite3.
 *
 * @module db/approval-queue-repository
 */

import type Database from 'better-sqlite3';
import { randomUUID } from 'crypto';
import type { ApprovalStatus, StepAction } from '../types/playbook.ts';
import type {
  ApprovalQueueEntry,
  CreateApprovalOptions,
  ListApprovalOptions,
} from '../types/simulation.ts';

// ---------------------------------------------------------------------------
// Internal Row Type
// ---------------------------------------------------------------------------

/**
 * Raw SQLite row shape for the approval_queue table.
 * All columns are TEXT (or null) — JSON fields are not yet parsed.
 */
interface ApprovalQueueRow {
  readonly request_id: string;
  readonly execution_id: string;
  readonly runbook_id: string;
  readonly runbook_name: string;
  readonly step_id: string;
  readonly step_name: string;
  readonly action: string;
  readonly parameters: string;
  readonly simulation_result: string;
  readonly status: string;
  readonly requested_at: string;
  readonly expires_at: string;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly denial_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

// ---------------------------------------------------------------------------
// Row-to-Entry Converter
// ---------------------------------------------------------------------------

/**
 * Convert a raw SQLite row into a typed {@link ApprovalQueueEntry}.
 *
 * JSON-serialized columns (`parameters`, `simulation_result`) are kept as
 * strings; the caller is responsible for parsing when needed.
 */
function toEntry(row: ApprovalQueueRow): ApprovalQueueEntry {
  return {
    request_id: row.request_id,
    execution_id: row.execution_id,
    runbook_id: row.runbook_id,
    runbook_name: row.runbook_name,
    step_id: row.step_id,
    step_name: row.step_name,
    action: row.action as StepAction,
    parameters: row.parameters,
    simulation_result: row.simulation_result,
    status: row.status as ApprovalStatus,
    requested_at: row.requested_at,
    expires_at: row.expires_at,
    approved_by: row.approved_by ?? undefined,
    approved_at: row.approved_at ?? undefined,
    denial_reason: row.denial_reason ?? undefined,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

export class ApprovalQueueRepository {
  private readonly db: Database.Database;

  // Prepared statements --------------------------------------------------

  private readonly stmtInsert: Database.Statement;
  private readonly stmtGetById: Database.Statement;
  private readonly stmtListByStatus: Database.Statement;
  private readonly stmtApprove: Database.Statement;
  private readonly stmtDeny: Database.Statement;
  private readonly stmtExpireStale: Database.Statement;
  private readonly stmtGetByExecutionId: Database.Statement;
  private readonly stmtDeleteByExecutionId: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.stmtInsert = db.prepare(`
      INSERT INTO approval_queue (
        request_id, execution_id, runbook_id, runbook_name,
        step_id, step_name, action, parameters, simulation_result,
        status, requested_at, expires_at,
        created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `);

    this.stmtGetById = db.prepare(
      'SELECT * FROM approval_queue WHERE request_id = ?',
    );

    this.stmtListByStatus = db.prepare(
      'SELECT * FROM approval_queue WHERE status = ? ORDER BY requested_at DESC LIMIT ?',
    );

    this.stmtApprove = db.prepare(`
      UPDATE approval_queue
      SET status = 'approved',
          approved_by = ?,
          approved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
          updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE request_id = ?
    `);

    this.stmtDeny = db.prepare(`
      UPDATE approval_queue
      SET status = 'denied',
          denial_reason = ?,
          updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE request_id = ?
    `);

    this.stmtExpireStale = db.prepare(`
      UPDATE approval_queue
      SET status = 'expired',
          updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE status = 'pending'
        AND expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    `);

    this.stmtGetByExecutionId = db.prepare(
      'SELECT * FROM approval_queue WHERE execution_id = ? ORDER BY requested_at DESC',
    );

    this.stmtDeleteByExecutionId = db.prepare(
      'DELETE FROM approval_queue WHERE execution_id = ?',
    );
  }

  // Public API -----------------------------------------------------------

  /**
   * Create a new approval queue entry.
   *
   * Generates a `request_id` via `randomUUID()`, sets the initial status to
   * `'pending'`, and computes `expires_at` from `requested_at + ttl_seconds`.
   *
   * @param options - Creation parameters including execution details and TTL.
   * @returns The newly created {@link ApprovalQueueEntry}.
   */
  create(options: CreateApprovalOptions): ApprovalQueueEntry {
    const requestId = randomUUID();
    const requestedAt = new Date().toISOString();
    const expiresAt = new Date(
      Date.now() + options.ttl_seconds * 1_000,
    ).toISOString();

    this.stmtInsert.run(
      requestId,
      options.execution_id,
      options.runbook_id,
      options.runbook_name,
      options.step_id,
      options.step_name,
      options.action,
      JSON.stringify(options.parameters),
      JSON.stringify(options.simulation_report),
      'pending',
      requestedAt,
      expiresAt,
    );

    // Re-fetch so created_at / updated_at come from SQLite
    const row = this.stmtGetById.get(requestId) as ApprovalQueueRow;
    return toEntry(row);
  }

  /**
   * Retrieve an approval queue entry by its request ID.
   *
   * @param requestId - The unique request identifier.
   * @returns The matching entry, or `undefined` if not found.
   */
  getById(requestId: string): ApprovalQueueEntry | undefined {
    const row = this.stmtGetById.get(requestId) as ApprovalQueueRow | undefined;
    return row ? toEntry(row) : undefined;
  }

  /**
   * List pending (non-expired) approval queue entries.
   *
   * Supports optional filtering by `execution_id` and `runbook_id`, plus
   * `limit` / `offset` for pagination. Results are ordered by
   * `requested_at DESC`.
   *
   * @param options - Optional filtering and pagination parameters.
   * @returns An array of pending {@link ApprovalQueueEntry} items.
   */
  listPending(options: ListApprovalOptions = {}): ApprovalQueueEntry[] {
    const conditions: string[] = [
      "status = 'pending'",
      "expires_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
    ];
    const params: unknown[] = [];

    if (options.execution_id) {
      conditions.push('execution_id = ?');
      params.push(options.execution_id);
    }
    if (options.runbook_id) {
      conditions.push('runbook_id = ?');
      params.push(options.runbook_id);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;

    const rows = this.db
      .prepare(
        `SELECT * FROM approval_queue ${where} ORDER BY requested_at DESC LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset) as ApprovalQueueRow[];

    return rows.map(toEntry);
  }

  /**
   * List approval queue entries filtered by status.
   *
   * @param status - The approval status to filter on.
   * @param limit  - Maximum number of entries to return (default 50).
   * @returns An array of matching {@link ApprovalQueueEntry} items.
   */
  listByStatus(status: ApprovalStatus, limit = 50): ApprovalQueueEntry[] {
    const rows = this.stmtListByStatus.all(status, limit) as ApprovalQueueRow[];
    return rows.map(toEntry);
  }

  /**
   * Approve a pending approval request.
   *
   * Sets `status = 'approved'`, records `approved_by` and `approved_at`.
   *
   * @param requestId  - The request to approve.
   * @param approvedBy - Identifier of the approving user.
   * @returns The updated {@link ApprovalQueueEntry}.
   * @throws {Error} If the entry does not exist, is not pending, or has expired.
   */
  approve(requestId: string, approvedBy: string): ApprovalQueueEntry {
    const existing = this.getById(requestId);

    if (!existing) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    if (existing.status !== 'pending') {
      throw new Error(
        `Cannot approve request with status '${existing.status}': ${requestId}`,
      );
    }
    if (new Date(existing.expires_at) < new Date()) {
      // Auto-expire before rejecting
      this.stmtExpireStale.run();
      throw new Error(`Approval request has expired: ${requestId}`);
    }

    this.stmtApprove.run(approvedBy, requestId);

    const updated = this.stmtGetById.get(requestId) as ApprovalQueueRow;
    return toEntry(updated);
  }

  /**
   * Deny a pending approval request.
   *
   * Sets `status = 'denied'` and records the `denial_reason`.
   *
   * @param requestId - The request to deny.
   * @param reason    - Human-readable reason for denial.
   * @returns The updated {@link ApprovalQueueEntry}.
   * @throws {Error} If the entry does not exist or is not pending.
   */
  deny(requestId: string, reason: string): ApprovalQueueEntry {
    const existing = this.getById(requestId);

    if (!existing) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    if (existing.status !== 'pending') {
      throw new Error(
        `Cannot deny request with status '${existing.status}': ${requestId}`,
      );
    }

    this.stmtDeny.run(reason, requestId);

    const updated = this.stmtGetById.get(requestId) as ApprovalQueueRow;
    return toEntry(updated);
  }

  /**
   * Expire all stale pending entries whose `expires_at` is in the past.
   *
   * @returns The number of entries that were expired.
   */
  expireStale(): number {
    const result = this.stmtExpireStale.run();
    return result.changes;
  }

  /**
   * Get all approval queue entries for a given execution.
   *
   * @param executionId - The execution identifier.
   * @returns An array of {@link ApprovalQueueEntry} items ordered by `requested_at DESC`.
   */
  getByExecutionId(executionId: string): ApprovalQueueEntry[] {
    const rows = this.stmtGetByExecutionId.all(executionId) as ApprovalQueueRow[];
    return rows.map(toEntry);
  }

  /**
   * Count approval queue entries grouped by status.
   *
   * @returns A record mapping each {@link ApprovalStatus} to its count.
   */
  countByStatus(): Record<ApprovalStatus, number> {
    const rows = this.db
      .prepare(
        'SELECT status, COUNT(*) as count FROM approval_queue GROUP BY status',
      )
      .all() as Array<{ status: string; count: number }>;

    const counts: Record<ApprovalStatus, number> = {
      pending: 0,
      approved: 0,
      denied: 0,
      expired: 0,
    };

    for (const row of rows) {
      counts[row.status as ApprovalStatus] = row.count;
    }

    return counts;
  }

  /**
   * Delete all approval queue entries for a given execution.
   *
   * @param executionId - The execution identifier.
   * @returns The number of entries deleted.
   */
  deleteByExecutionId(executionId: string): number {
    const result = this.stmtDeleteByExecutionId.run(executionId);
    return result.changes;
  }
}

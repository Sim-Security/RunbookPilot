/**
 * Execution History Repository
 *
 * Persistence layer for execution state, step results, and history queries.
 * Uses SQLite via better-sqlite3.
 *
 * @module db/execution-repository
 */

import type Database from 'better-sqlite3';
import type {
  ExecutionState,
  ExecutionMode,
  StepResult,
} from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ExecutionRecord {
  execution_id: string;
  runbook_id: string;
  runbook_version: string;
  runbook_name: string;
  state: ExecutionState;
  mode: ExecutionMode;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  context_snapshot?: string; // JSON
  error?: string; // JSON
  created_at: string;
  updated_at: string;
}

export interface ExecutionQuery {
  runbookId?: string;
  state?: ExecutionState;
  mode?: ExecutionMode;
  startedAfter?: string;
  startedBefore?: string;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

export class ExecutionRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Create a new execution record.
   */
  createExecution(params: {
    executionId: string;
    runbookId: string;
    runbookVersion: string;
    runbookName: string;
    mode: ExecutionMode;
    contextSnapshot?: Record<string, unknown>;
  }): void {
    this.db.prepare(`
      INSERT INTO executions (
        execution_id, runbook_id, runbook_version, runbook_name,
        state, mode, started_at, context_snapshot
      ) VALUES (?, ?, ?, ?, 'idle', ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?)
    `).run(
      params.executionId,
      params.runbookId,
      params.runbookVersion,
      params.runbookName,
      params.mode,
      params.contextSnapshot ? JSON.stringify(params.contextSnapshot) : null,
    );
  }

  /**
   * Update execution state.
   */
  updateState(executionId: string, state: ExecutionState): void {
    this.db.prepare(`
      UPDATE executions
      SET state = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE execution_id = ?
    `).run(state, executionId);
  }

  /**
   * Complete an execution (success or failure).
   */
  completeExecution(executionId: string, params: {
    state: ExecutionState;
    durationMs: number;
    error?: Record<string, unknown>;
    contextSnapshot?: Record<string, unknown>;
  }): void {
    this.db.prepare(`
      UPDATE executions
      SET state = ?,
          completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
          duration_ms = ?,
          error = ?,
          context_snapshot = ?,
          updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE execution_id = ?
    `).run(
      params.state,
      params.durationMs,
      params.error ? JSON.stringify(params.error) : null,
      params.contextSnapshot ? JSON.stringify(params.contextSnapshot) : null,
      executionId,
    );
  }

  /**
   * Save a step result.
   */
  saveStepResult(executionId: string, result: StepResult): void {
    this.db.prepare(`
      INSERT INTO step_results (
        execution_id, step_id, step_name, action, success,
        started_at, completed_at, duration_ms, output, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      executionId,
      result.step_id,
      result.step_name,
      result.action,
      result.success ? 1 : 0,
      result.started_at,
      result.completed_at,
      result.duration_ms,
      result.output ? JSON.stringify(result.output) : null,
      result.error ? JSON.stringify(result.error) : null,
    );
  }

  /**
   * Get execution by ID.
   */
  getExecution(executionId: string): ExecutionRecord | undefined {
    const row = this.db.prepare(
      'SELECT * FROM executions WHERE execution_id = ?',
    ).get(executionId) as ExecutionRecord | undefined;
    return row;
  }

  /**
   * Get step results for an execution.
   */
  getStepResults(executionId: string): StepResult[] {
    const rows = this.db.prepare(
      'SELECT * FROM step_results WHERE execution_id = ? ORDER BY started_at',
    ).all(executionId) as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      step_id: row['step_id'] as string,
      step_name: row['step_name'] as string,
      action: row['action'] as StepResult['action'],
      success: row['success'] === 1,
      started_at: row['started_at'] as string,
      completed_at: row['completed_at'] as string,
      duration_ms: row['duration_ms'] as number,
      output: row['output'] ? JSON.parse(row['output'] as string) : undefined,
      error: row['error'] ? JSON.parse(row['error'] as string) : undefined,
    }));
  }

  /**
   * Query executions with filters.
   */
  queryExecutions(query: ExecutionQuery = {}): ExecutionRecord[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.runbookId) {
      conditions.push('runbook_id = ?');
      params.push(query.runbookId);
    }
    if (query.state) {
      conditions.push('state = ?');
      params.push(query.state);
    }
    if (query.mode) {
      conditions.push('mode = ?');
      params.push(query.mode);
    }
    if (query.startedAfter) {
      conditions.push('started_at >= ?');
      params.push(query.startedAfter);
    }
    if (query.startedBefore) {
      conditions.push('started_at <= ?');
      params.push(query.startedBefore);
    }

    const where = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';
    const limit = query.limit ?? 50;
    const offset = query.offset ?? 0;

    const rows = this.db.prepare(
      `SELECT * FROM executions ${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
    ).all(...params, limit, offset) as ExecutionRecord[];

    return rows;
  }

  /**
   * Count executions matching filters.
   */
  countExecutions(query: Omit<ExecutionQuery, 'limit' | 'offset'> = {}): number {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.runbookId) {
      conditions.push('runbook_id = ?');
      params.push(query.runbookId);
    }
    if (query.state) {
      conditions.push('state = ?');
      params.push(query.state);
    }

    const where = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const row = this.db.prepare(
      `SELECT COUNT(*) as count FROM executions ${where}`,
    ).get(...params) as { count: number };

    return row.count;
  }
}

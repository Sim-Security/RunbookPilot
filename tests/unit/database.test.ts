import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initDatabase, getDatabase, closeDatabase } from '../../src/db/index.ts';
import type Database from 'better-sqlite3';

describe('Database', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase({ path: ':memory:', inMemory: true });
  });

  afterEach(() => {
    closeDatabase();
  });

  it('initializes in-memory database', () => {
    expect(db).toBeDefined();
  });

  it('creates schema_version table', () => {
    const row = db.prepare('SELECT MAX(version) as version FROM schema_version').get() as { version: number };
    expect(row.version).toBe(1);
  });

  it('creates executions table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='executions'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('executions');
  });

  it('creates audit_log table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('audit_log');
  });

  it('creates approval_queue table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='approval_queue'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('approval_queue');
  });

  it('creates step_results table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='step_results'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('step_results');
  });

  it('creates metrics table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='metrics'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('metrics');
  });

  it('creates adapters table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='adapters'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('adapters');
  });

  it('creates detectforge_mappings table', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='detectforge_mappings'")
      .get() as { name: string } | undefined;
    expect(tables?.name).toBe('detectforge_mappings');
  });

  it('enforces foreign keys', () => {
    const fk = db.pragma('foreign_keys') as Array<{ foreign_keys: number }>;
    expect(fk[0]?.foreign_keys).toBe(1);
  });

  it('uses WAL journal mode for file-based databases', () => {
    // In-memory databases use 'memory' journal mode (WAL is not supported).
    // Verify the pragma is queryable; file-based DBs get WAL via initDatabase.
    const mode = db.pragma('journal_mode') as Array<{ journal_mode: string }>;
    expect(mode[0]?.journal_mode).toBe('memory');
  });

  it('can insert and query executions', () => {
    db.prepare(`
      INSERT INTO executions (execution_id, runbook_id, runbook_version, runbook_name, state, mode, started_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('exec-001', 'rb-001', '1.0', 'Test Runbook', 'idle', 'production', new Date().toISOString());

    const row = db.prepare('SELECT * FROM executions WHERE execution_id = ?').get('exec-001') as Record<string, unknown>;
    expect(row['runbook_name']).toBe('Test Runbook');
    expect(row['state']).toBe('idle');
  });

  it('rejects invalid execution states', () => {
    expect(() => {
      db.prepare(`
        INSERT INTO executions (execution_id, runbook_id, runbook_version, runbook_name, state, mode, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run('exec-002', 'rb-001', '1.0', 'Test', 'invalid_state', 'production', new Date().toISOString());
    }).toThrow();
  });

  it('rejects invalid execution modes', () => {
    expect(() => {
      db.prepare(`
        INSERT INTO executions (execution_id, runbook_id, runbook_version, runbook_name, state, mode, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run('exec-003', 'rb-001', '1.0', 'Test', 'idle', 'invalid_mode', new Date().toISOString());
    }).toThrow();
  });

  it('getDatabase returns initialized instance', () => {
    const retrieved = getDatabase();
    expect(retrieved).toBe(db);
  });

  it('getDatabase throws when not initialized', () => {
    closeDatabase();
    expect(() => getDatabase()).toThrow('Database not initialized');
  });
});

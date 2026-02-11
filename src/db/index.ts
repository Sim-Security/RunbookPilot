import Database from 'better-sqlite3';
import { readFileSync, mkdirSync, existsSync } from 'fs';
import { dirname, resolve } from 'path';
import { logger } from '../logging/logger.ts';

const SCHEMA_PATH = resolve(import.meta.dirname ?? '.', 'schema.sql');

let _db: Database.Database | null = null;

export interface DatabaseOptions {
  path: string;
  readonly?: boolean;
  inMemory?: boolean;
}

/**
 * Initialize the SQLite database with schema.
 * Uses WAL mode for concurrent read access.
 */
export function initDatabase(options: DatabaseOptions): Database.Database {
  const log = logger.child({ component: 'database' });

  let db: Database.Database;

  if (options.inMemory) {
    db = new Database(':memory:');
    log.info('Initialized in-memory database');
  } else {
    const dbDir = dirname(options.path);
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
      log.info('Created database directory', { path: dbDir });
    }

    db = new Database(options.path, {
      readonly: options.readonly ?? false,
    });
    log.info('Opened database', { path: options.path });
  }

  // Enable WAL mode for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');

  // Run schema
  applySchema(db);

  // Run migrations
  runMigrations(db);

  _db = db;
  return db;
}

/**
 * Apply the base schema SQL.
 */
function applySchema(db: Database.Database): void {
  const log = logger.child({ component: 'database' });

  try {
    const schema = readFileSync(SCHEMA_PATH, 'utf-8');
    db.exec(schema);
    log.debug('Database schema applied');
  } catch (error) {
    log.error('Failed to apply database schema', {
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

/**
 * Run any pending migrations.
 */
function runMigrations(db: Database.Database): void {
  const log = logger.child({ component: 'database' });

  const currentVersion = db
    .prepare('SELECT MAX(version) as version FROM schema_version')
    .get() as { version: number } | undefined;

  const version = currentVersion?.version ?? 0;
  log.debug('Current schema version', { version });

  // Future migrations go here
  const migrations: Array<{ version: number; up: (db: Database.Database) => void }> = [
    // Example:
    // { version: 2, up: (db) => db.exec('ALTER TABLE ...') },
  ];

  for (const migration of migrations) {
    if (migration.version > version) {
      log.info('Applying migration', { version: migration.version });
      migration.up(db);
      db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(
        migration.version,
      );
    }
  }
}

/**
 * Get the current database instance.
 * Throws if database has not been initialized.
 */
export function getDatabase(): Database.Database {
  if (!_db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return _db;
}

/**
 * Close the database connection.
 */
export function closeDatabase(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

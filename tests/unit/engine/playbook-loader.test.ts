import { describe, it, expect, beforeEach } from 'vitest';
import { resolve, join } from 'path';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';

import {
  loadPlaybook,
  loadPlaybookFromString,
  listPlaybooks,
  getPlaybookCache,
  clearPlaybookCache,
} from '../../../src/engine/playbook-loader.ts';

import type {
  PlaybookLoadResult,
  PlaybookInfo,
  CachedPlaybook,
} from '../../../src/engine/playbook-loader.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASIC_PLAYBOOK_PATH = 'playbooks/examples/basic.yml';

const VALID_YAML = `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  metadata:
    name: "Test Playbook"
    description: "A valid playbook for testing"
    author: "test@example.com"
    created: "2026-01-15T10:00:00Z"
    updated: "2026-01-15T10:00:00Z"
    tags:
      - "test"
      - "phishing"
  triggers:
    detection_sources:
      - "manual"
    mitre_techniques:
      - "T1566"
    platforms:
      - "windows"
  config:
    automation_level: "L0"
    max_execution_time: 300
    requires_approval: false
  steps:
    - id: "step-01"
      name: "Collect Data"
      action: "collect_logs"
      executor: "siem"
      parameters:
        query: "index=auth"
      on_error: "halt"
      timeout: 30
`;

const INVALID_SCHEMA_YAML = `
runbook:
  id: "not-a-valid-uuid"
  version: "1.0"
  metadata:
    name: "Bad ID Playbook"
    created: "2026-01-15T10:00:00Z"
    updated: "2026-01-15T10:00:00Z"
    tags:
      - "test"
  triggers:
    detection_sources:
      - "manual"
    mitre_techniques:
      - "T1566"
    platforms:
      - "windows"
  config:
    automation_level: "L0"
    max_execution_time: 300
    requires_approval: false
  steps:
    - id: "step-01"
      name: "Collect Data"
      action: "collect_logs"
      executor: "siem"
      parameters:
        query: "test"
      on_error: "halt"
      timeout: 30
`;

const INVALID_YAML_SYNTAX = `
runbook:
  id: "test
  this is: [not valid yaml {{{
`;

/**
 * Create a temporary directory with optional YAML files for listing tests.
 */
function createTempPlaybookDir(files: Record<string, string>): string {
  const dir = join(tmpdir(), `rbp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content, 'utf-8');
  }
  return dir;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Playbook Loader', () => {
  beforeEach(() => {
    clearPlaybookCache();
  });

  // -----------------------------------------------------------------------
  // loadPlaybook (from file)
  // -----------------------------------------------------------------------

  describe('loadPlaybook', () => {
    it('loads and validates the example basic.yml playbook', () => {
      const result: PlaybookLoadResult = loadPlaybook(BASIC_PLAYBOOK_PATH);

      expect(result.success).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.playbook).toBeDefined();
      expect(result.filePath).toBeDefined();

      // Verify key fields from the known basic.yml content
      expect(result.playbook?.id).toBe('a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d');
      expect(result.playbook?.version).toBe('1.0');
      expect(result.playbook?.metadata.name).toBe('T1566.001 - Phishing Email Investigation');
      expect(result.playbook?.config.automation_level).toBe('L0');
      expect(result.playbook?.steps.length).toBe(4);
    });

    it('returns resolved absolute path in filePath', () => {
      const result = loadPlaybook(BASIC_PLAYBOOK_PATH);
      const expectedPath = resolve(BASIC_PLAYBOOK_PATH);

      expect(result.filePath).toBe(expectedPath);
    });

    it('handles missing files gracefully without throwing', () => {
      const result = loadPlaybook('/nonexistent/path/to/playbook.yml');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('File not found');
      expect(result.playbook).toBeUndefined();
    });

    it('handles a relative path to a missing file gracefully', () => {
      const result = loadPlaybook('does-not-exist.yml');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.playbook).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // loadPlaybookFromString
  // -----------------------------------------------------------------------

  describe('loadPlaybookFromString', () => {
    it('loads and validates a valid YAML string', () => {
      const result: PlaybookLoadResult = loadPlaybookFromString(VALID_YAML);

      expect(result.success).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.playbook).toBeDefined();
      expect(result.playbook?.id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(result.playbook?.metadata.name).toBe('Test Playbook');
      expect(result.playbook?.config.automation_level).toBe('L0');
      expect(result.playbook?.steps.length).toBe(1);
    });

    it('returns no filePath when loading from string', () => {
      const result = loadPlaybookFromString(VALID_YAML);

      expect(result.filePath).toBeUndefined();
    });

    it('handles invalid YAML syntax gracefully', () => {
      const result = loadPlaybookFromString(INVALID_YAML_SYNTAX);

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.playbook).toBeUndefined();
    });

    it('handles valid YAML that fails schema validation', () => {
      const result = loadPlaybookFromString(INVALID_SCHEMA_YAML);

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(e => e.includes('UUID'))).toBe(true);
      expect(result.playbook).toBeUndefined();
    });

    it('handles empty string gracefully', () => {
      const result = loadPlaybookFromString('');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.playbook).toBeUndefined();
    });

    it('handles YAML that parses to a non-object', () => {
      const result = loadPlaybookFromString('just a plain string');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.playbook).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // Caching
  // -----------------------------------------------------------------------

  describe('caching', () => {
    it('caches a successfully loaded playbook', () => {
      const result = loadPlaybook(BASIC_PLAYBOOK_PATH);
      expect(result.success).toBe(true);

      const cache = getPlaybookCache();
      const absolutePath = resolve(BASIC_PLAYBOOK_PATH);

      expect(cache.size).toBe(1);
      expect(cache.has(absolutePath)).toBe(true);

      const cached: CachedPlaybook | undefined = cache.get(absolutePath);
      expect(cached).toBeDefined();
      expect(cached?.playbook.id).toBe('a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d');
      expect(cached?.filePath).toBe(absolutePath);
      expect(typeof cached?.loadedAt).toBe('number');
    });

    it('returns cached playbook on second load without re-reading file', () => {
      // First load
      const result1 = loadPlaybook(BASIC_PLAYBOOK_PATH);
      expect(result1.success).toBe(true);

      const cache = getPlaybookCache();
      const absolutePath = resolve(BASIC_PLAYBOOK_PATH);
      const cachedEntry = cache.get(absolutePath);
      const loadedAt = cachedEntry?.loadedAt;

      // Second load -- should return from cache
      const result2 = loadPlaybook(BASIC_PLAYBOOK_PATH);
      expect(result2.success).toBe(true);
      expect(result2.playbook).toBe(result1.playbook); // Same reference

      // Cache entry should not have changed
      const cachedEntry2 = cache.get(absolutePath);
      expect(cachedEntry2?.loadedAt).toBe(loadedAt);
    });

    it('does not cache failed loads', () => {
      const result = loadPlaybook('/nonexistent/playbook.yml');
      expect(result.success).toBe(false);

      const cache = getPlaybookCache();
      expect(cache.size).toBe(0);
    });

    it('does not cache string-loaded playbooks', () => {
      const result = loadPlaybookFromString(VALID_YAML);
      expect(result.success).toBe(true);

      const cache = getPlaybookCache();
      expect(cache.size).toBe(0);
    });

    it('clears the cache', () => {
      // Load to populate
      loadPlaybook(BASIC_PLAYBOOK_PATH);
      expect(getPlaybookCache().size).toBe(1);

      // Clear
      clearPlaybookCache();
      expect(getPlaybookCache().size).toBe(0);
    });

    it('clearing an empty cache is a no-op', () => {
      expect(getPlaybookCache().size).toBe(0);
      clearPlaybookCache();
      expect(getPlaybookCache().size).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // listPlaybooks
  // -----------------------------------------------------------------------

  describe('listPlaybooks', () => {
    it('lists playbooks from the examples directory', () => {
      const playbooks: PlaybookInfo[] = listPlaybooks('playbooks/examples');

      expect(playbooks.length).toBeGreaterThanOrEqual(1);

      const basic = playbooks.find(p => p.filePath.includes('basic.yml'));
      expect(basic).toBeDefined();
      expect(basic?.name).toBe('T1566.001 - Phishing Email Investigation');
      expect(basic?.automationLevel).toBe('L0');
      expect(basic?.version).toBe('1.0');
    });

    it('returns empty array for nonexistent directory', () => {
      const playbooks = listPlaybooks('/nonexistent/directory');

      expect(playbooks).toEqual([]);
    });

    it('returns empty array for directory with no YAML files', () => {
      const dir = createTempPlaybookDir({
        'readme.txt': 'not a yaml file',
        'data.json': '{"key": "value"}',
      });

      try {
        const playbooks = listPlaybooks(dir);
        expect(playbooks).toEqual([]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('lists multiple YAML files from a temp directory', () => {
      const playbookA = `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "2.0"
  metadata:
    name: "Playbook Alpha"
  config:
    automation_level: "L1"
`;

      const playbookB = `
runbook:
  id: "660e8400-e29b-41d4-a716-446655440000"
  version: "3.1"
  metadata:
    name: "Playbook Beta"
  config:
    automation_level: "L2"
`;

      const dir = createTempPlaybookDir({
        'alpha.yml': playbookA,
        'beta.yaml': playbookB,
        'ignore.txt': 'not a playbook',
      });

      try {
        const playbooks = listPlaybooks(dir);

        expect(playbooks.length).toBe(2);

        const alpha = playbooks.find(p => p.name === 'Playbook Alpha');
        expect(alpha).toBeDefined();
        expect(alpha?.automationLevel).toBe('L1');
        expect(alpha?.version).toBe('2.0');
        expect(alpha?.filePath).toContain('alpha.yml');

        const beta = playbooks.find(p => p.name === 'Playbook Beta');
        expect(beta).toBeDefined();
        expect(beta?.automationLevel).toBe('L2');
        expect(beta?.version).toBe('3.1');
        expect(beta?.filePath).toContain('beta.yaml');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('skips YAML files that cannot be parsed', () => {
      const dir = createTempPlaybookDir({
        'valid.yml': `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  metadata:
    name: "Valid One"
  config:
    automation_level: "L0"
`,
        'broken.yml': '{ broken yaml [[[',
      });

      try {
        const playbooks = listPlaybooks(dir);

        // Only the valid file should appear
        expect(playbooks.length).toBe(1);
        expect(playbooks[0]?.name).toBe('Valid One');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('skips YAML files without a runbook top-level key', () => {
      const dir = createTempPlaybookDir({
        'notarunbook.yml': `
name: "Some Other Config"
version: "1.0"
`,
      });

      try {
        const playbooks = listPlaybooks(dir);
        expect(playbooks).toEqual([]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('uses filename as fallback when metadata.name is missing', () => {
      const dir = createTempPlaybookDir({
        'unnamed.yml': `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  config:
    automation_level: "L0"
`,
      });

      try {
        const playbooks = listPlaybooks(dir);

        expect(playbooks.length).toBe(1);
        expect(playbooks[0]?.name).toBe('unnamed');
        expect(playbooks[0]?.automationLevel).toBe('L0');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('reports "unknown" for missing automation_level and version', () => {
      const dir = createTempPlaybookDir({
        'minimal.yml': `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  metadata:
    name: "Minimal"
`,
      });

      try {
        const playbooks = listPlaybooks(dir);

        expect(playbooks.length).toBe(1);
        expect(playbooks[0]?.automationLevel).toBe('unknown');
        expect(playbooks[0]?.version).toBe('unknown');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // -----------------------------------------------------------------------
  // Return type contracts
  // -----------------------------------------------------------------------

  describe('return type contracts', () => {
    it('PlaybookLoadResult always has success and errors fields', () => {
      const successResult = loadPlaybookFromString(VALID_YAML);
      expect(typeof successResult.success).toBe('boolean');
      expect(Array.isArray(successResult.errors)).toBe(true);

      const failResult = loadPlaybook('/nonexistent.yml');
      expect(typeof failResult.success).toBe('boolean');
      expect(Array.isArray(failResult.errors)).toBe(true);
    });

    it('successful result has playbook defined, failed result does not', () => {
      const successResult = loadPlaybookFromString(VALID_YAML);
      expect(successResult.success).toBe(true);
      expect(successResult.playbook).toBeDefined();

      const failResult = loadPlaybookFromString(INVALID_YAML_SYNTAX);
      expect(failResult.success).toBe(false);
      expect(failResult.playbook).toBeUndefined();
    });
  });
});

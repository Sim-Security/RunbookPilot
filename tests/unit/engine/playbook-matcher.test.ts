import { describe, it, expect, beforeEach } from 'vitest';
import { PlaybookMatcher } from '../../../src/engine/playbook-matcher.ts';
import type { TechniqueMapping } from '../../../src/engine/playbook-matcher.ts';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// Test Constants
// ---------------------------------------------------------------------------

const REAL_CONFIG_PATH = resolve(
  process.cwd(),
  'config/technique-playbook-map.yml',
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMapping(overrides: Partial<TechniqueMapping> = {}): TechniqueMapping {
  return {
    technique_id: 'T9999',
    technique_name: 'Test Technique',
    tactic: 'test-tactic',
    playbook_files: ['playbooks/test-playbook.yml'],
    default_level: 'L0',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// PlaybookMatcher: Loading from YAML
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - loadMapping', () => {
  it('loads mappings from the real YAML config file', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);

    expect(matcher.size).toBeGreaterThan(0);
  });

  it('loads all expected technique mappings from config', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    const mappings = matcher.getMapping();

    // The config has 11 entries
    expect(mappings.length).toBe(11);

    // Spot-check a few
    const lsass = mappings.find((m) => m.technique_id === 'T1003.001');
    expect(lsass).toBeDefined();
    expect(lsass!.technique_name).toBe('LSASS Memory');
    expect(lsass!.tactic).toBe('credential-access');
    expect(lsass!.default_level).toBe('L0');
  });

  it('loads the global default_playbook from config', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    expect(matcher.getGlobalDefault()).toBe('playbooks/generic-triage-l0.yml');
  });

  it('handles missing file gracefully (stderr warning, empty mappings)', () => {
    const matcher = new PlaybookMatcher('/nonexistent/path/to/config.yml');

    expect(matcher.size).toBe(0);
    expect(matcher.getGlobalDefault()).toBeUndefined();
  });

  it('reloads mapping clears previous state', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    expect(matcher.size).toBeGreaterThan(0);

    // Reload with a nonexistent file clears everything
    matcher.loadMapping('/nonexistent/file.yml');
    expect(matcher.size).toBe(0);
    expect(matcher.getGlobalDefault()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: match()
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - match', () => {
  let matcher: PlaybookMatcher;

  beforeEach(() => {
    matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
  });

  it('returns MatchResult for exact technique ID match', () => {
    const result = matcher.match('T1003.001');

    expect(result).toBeDefined();
    expect(result!.technique_id).toBe('T1003.001');
    expect(result!.matched_playbooks).toContain('playbooks/lsass-credential-dumping-l0.yml');
    expect(result!.default_level).toBe('L0');
    expect(result!.confidence).toBe(1.0);
  });

  it('matches case-insensitively', () => {
    const result = matcher.match('t1003.001');

    expect(result).toBeDefined();
    expect(result!.technique_id).toBe('T1003.001');
  });

  it('matches with leading/trailing whitespace', () => {
    const result = matcher.match('  T1003.001  ');

    expect(result).toBeDefined();
    expect(result!.technique_id).toBe('T1003.001');
  });

  it('returns undefined for unknown technique ID', () => {
    const result = matcher.match('T9999.999');

    expect(result).toBeUndefined();
  });

  it('returns multiple playbook files for techniques with multiple playbooks', () => {
    const result = matcher.match('T1059.001');

    expect(result).toBeDefined();
    expect(result!.matched_playbooks).toHaveLength(2);
    expect(result!.matched_playbooks).toContain('playbooks/powershell-execution-l0.yml');
    expect(result!.matched_playbooks).toContain('playbooks/powershell-execution-l1.yml');
  });

  it('returns L1 default level for WMI technique', () => {
    const result = matcher.match('T1047');

    expect(result).toBeDefined();
    expect(result!.default_level).toBe('L1');
  });

  it('returns L2 default level for Cobalt Strike technique', () => {
    const result = matcher.match('T1071.001');

    expect(result).toBeDefined();
    expect(result!.default_level).toBe('L2');
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: matchByTactic()
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - matchByTactic', () => {
  let matcher: PlaybookMatcher;

  beforeEach(() => {
    matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
  });

  it('finds all playbooks for a tactic', () => {
    const results = matcher.matchByTactic('execution');

    // T1047 (WMI) and T1059.001 (PowerShell) are both 'execution'
    expect(results.length).toBe(2);
    expect(results.some((r) => r.technique_id === 'T1047')).toBe(true);
    expect(results.some((r) => r.technique_id === 'T1059.001')).toBe(true);
  });

  it('returns confidence 0.5 for tactic-level matches', () => {
    const results = matcher.matchByTactic('execution');

    for (const result of results) {
      expect(result.confidence).toBe(0.5);
    }
  });

  it('returns empty array for unknown tactic', () => {
    const results = matcher.matchByTactic('nonexistent-tactic');

    expect(results).toEqual([]);
  });

  it('matches tactic case-insensitively', () => {
    const results = matcher.matchByTactic('EXECUTION');

    expect(results.length).toBe(2);
  });

  it('finds single playbook for unique tactic', () => {
    const results = matcher.matchByTactic('command-and-control');

    expect(results.length).toBe(1);
    expect(results[0]!.technique_id).toBe('T1071.001');
  });

  it('finds playbooks for initial-access tactic', () => {
    const results = matcher.matchByTactic('initial-access');

    expect(results.length).toBe(2);
    expect(results.some((r) => r.technique_id === 'T1566.001')).toBe(true);
    expect(results.some((r) => r.technique_id === 'T1190')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: getDefaultPlaybook()
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - getDefaultPlaybook', () => {
  let matcher: PlaybookMatcher;

  beforeEach(() => {
    matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
  });

  it('returns first playbook for a known technique', () => {
    const result = matcher.getDefaultPlaybook('T1003.001');

    expect(result).toBe('playbooks/lsass-credential-dumping-l0.yml');
  });

  it('returns first playbook for technique with multiple playbooks', () => {
    const result = matcher.getDefaultPlaybook('T1059.001');

    expect(result).toBe('playbooks/powershell-execution-l0.yml');
  });

  it('returns global fallback for unknown technique', () => {
    const result = matcher.getDefaultPlaybook('T9999.999');

    expect(result).toBe('playbooks/generic-triage-l0.yml');
  });

  it('returns undefined when no global default and technique unknown', () => {
    const matcher2 = new PlaybookMatcher('/nonexistent/file.yml');
    const result = matcher2.getDefaultPlaybook('T9999.999');

    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: addMapping()
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - addMapping', () => {
  let matcher: PlaybookMatcher;

  beforeEach(() => {
    matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
  });

  it('adds a new mapping at runtime', () => {
    const sizeBefore = matcher.size;
    matcher.addMapping(makeMapping());

    expect(matcher.size).toBe(sizeBefore + 1);
    expect(matcher.match('T9999')).toBeDefined();
    expect(matcher.match('T9999')!.matched_playbooks).toContain('playbooks/test-playbook.yml');
  });

  it('replaces an existing mapping with the same technique_id', () => {
    matcher.addMapping(makeMapping({
      technique_id: 'T1003.001',
      technique_name: 'Updated LSASS',
      tactic: 'credential-access',
      playbook_files: ['playbooks/new-lsass-playbook.yml'],
      default_level: 'L1',
    }));

    const result = matcher.match('T1003.001');
    expect(result).toBeDefined();
    expect(result!.matched_playbooks).toContain('playbooks/new-lsass-playbook.yml');
    expect(result!.default_level).toBe('L1');
  });

  it('replaces existing mapping case-insensitively', () => {
    const sizeBefore = matcher.size;

    matcher.addMapping(makeMapping({
      technique_id: 't1003.001', // lowercase
      technique_name: 'Updated LSASS',
      tactic: 'credential-access',
      playbook_files: ['playbooks/updated.yml'],
      default_level: 'L2',
    }));

    // Size should not increase (replaced)
    expect(matcher.size).toBe(sizeBefore);
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: getMapping()
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - getMapping', () => {
  it('returns a copy of all mappings', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    const mappings = matcher.getMapping();

    expect(Array.isArray(mappings)).toBe(true);
    expect(mappings.length).toBe(matcher.size);

    // Mutating the returned array should not affect internal state
    mappings.pop();
    expect(matcher.size).toBeGreaterThan(mappings.length);
  });

  it('returns empty array when no mappings loaded', () => {
    const matcher = new PlaybookMatcher('/nonexistent/file.yml');
    const mappings = matcher.getMapping();

    expect(mappings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PlaybookMatcher: size getter
// ---------------------------------------------------------------------------

describe('PlaybookMatcher - size', () => {
  it('returns 0 for empty matcher', () => {
    const matcher = new PlaybookMatcher('/nonexistent/file.yml');
    expect(matcher.size).toBe(0);
  });

  it('returns correct count after loading from YAML', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    expect(matcher.size).toBe(11);
  });

  it('increases after addMapping with new technique', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    const before = matcher.size;

    matcher.addMapping(makeMapping());
    expect(matcher.size).toBe(before + 1);
  });

  it('stays the same after addMapping replacing existing technique', () => {
    const matcher = new PlaybookMatcher(REAL_CONFIG_PATH);
    const before = matcher.size;

    matcher.addMapping(makeMapping({ technique_id: 'T1003.001' }));
    expect(matcher.size).toBe(before);
  });
});

/**
 * RunbookPilot Playbook Matcher
 *
 * Maps MITRE ATT&CK technique IDs to playbook files using a YAML
 * configuration file (config/technique-playbook-map.yml).
 *
 * Supports exact technique matching, tactic-level matching, and
 * runtime additions to the mapping table.
 *
 * @module engine/playbook-matcher
 */

import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { parse as parseYaml } from 'yaml';

import type { AutomationLevel } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * A single technique-to-playbook mapping entry.
 */
export interface TechniqueMapping {
  technique_id: string;      // e.g., 'T1003.001'
  technique_name: string;    // e.g., 'LSASS Memory'
  tactic: string;            // e.g., 'credential-access'
  playbook_files: string[];  // e.g., ['playbooks/lsass-l0.yml']
  default_level: AutomationLevel;
}

/**
 * Result of matching a technique ID or tactic to playbooks.
 */
export interface MatchResult {
  technique_id: string;
  matched_playbooks: string[];
  default_level: AutomationLevel;
  confidence: number; // 1.0 for exact match, 0.5 for tactic-level
}

// ---------------------------------------------------------------------------
// Internal Types (YAML structure)
// ---------------------------------------------------------------------------

interface YamlMappingEntry {
  technique_id?: string;
  technique_name?: string;
  tactic?: string;
  playbook_files?: string[];
  default_level?: string;
}

interface YamlMappingFile {
  version?: string;
  description?: string;
  default_playbook?: string;
  mappings?: YamlMappingEntry[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG_PATH = 'config/technique-playbook-map.yml';
const VALID_LEVELS = new Set<AutomationLevel>(['L0', 'L1', 'L2']);

// ---------------------------------------------------------------------------
// PlaybookMatcher Class
// ---------------------------------------------------------------------------

/**
 * Maps ATT&CK technique IDs to RunbookPilot playbook files.
 *
 * Loads mappings from a YAML configuration file and provides methods
 * for exact technique matching, tactic-level matching, and runtime
 * additions.
 */
export class PlaybookMatcher {
  private mappings: TechniqueMapping[] = [];
  private defaultPlaybook: string | undefined;

  /**
   * Create a new PlaybookMatcher.
   *
   * @param configPath - Optional path to the technique-playbook-map.yml file.
   *                     Defaults to 'config/technique-playbook-map.yml' relative to cwd.
   */
  constructor(configPath?: string) {
    const resolvedPath = configPath ?? DEFAULT_CONFIG_PATH;
    this.loadMapping(resolvedPath);
  }

  /**
   * Load (or reload) the technique-to-playbook mapping from a YAML file.
   *
   * Replaces any existing mappings. If the file does not exist or cannot
   * be parsed, the mapping list is cleared and a warning is logged to stderr.
   *
   * @param configPath - Path to the YAML mapping file.
   */
  loadMapping(configPath: string): void {
    this.mappings = [];
    this.defaultPlaybook = undefined;

    const absolutePath = resolve(configPath);

    if (!existsSync(absolutePath)) {
      process.stderr.write(
        `[PlaybookMatcher] Warning: mapping file not found: ${absolutePath}\n`,
      );
      return;
    }

    let raw: string;
    try {
      raw = readFileSync(absolutePath, 'utf-8');
    } catch (err: unknown) {
      process.stderr.write(
        `[PlaybookMatcher] Warning: could not read mapping file: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      return;
    }

    let parsed: unknown;
    try {
      parsed = parseYaml(raw);
    } catch (err: unknown) {
      process.stderr.write(
        `[PlaybookMatcher] Warning: could not parse YAML: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      return;
    }

    if (parsed === null || parsed === undefined || typeof parsed !== 'object') {
      return;
    }

    const file = parsed as YamlMappingFile;

    if (typeof file.default_playbook === 'string' && file.default_playbook.length > 0) {
      this.defaultPlaybook = file.default_playbook;
    }

    if (!Array.isArray(file.mappings)) {
      return;
    }

    for (const entry of file.mappings) {
      const mapping = this.parseEntry(entry);
      if (mapping) {
        this.mappings.push(mapping);
      }
    }
  }

  /**
   * Find an exact match for a technique ID.
   *
   * Matches are case-insensitive and support both full sub-technique IDs
   * (e.g., 'T1003.001') and parent technique IDs (e.g., 'T1003').
   *
   * @param techniqueId - MITRE ATT&CK technique ID (e.g., 'T1003.001').
   * @returns A MatchResult with confidence 1.0, or undefined if no match.
   */
  match(techniqueId: string): MatchResult | undefined {
    const normalized = techniqueId.toUpperCase().trim();

    const found = this.mappings.find(
      (m) => m.technique_id.toUpperCase() === normalized,
    );

    if (!found) {
      return undefined;
    }

    return {
      technique_id: found.technique_id,
      matched_playbooks: [...found.playbook_files],
      default_level: found.default_level,
      confidence: 1.0,
    };
  }

  /**
   * Find all playbooks mapped to a given tactic.
   *
   * Returns results with confidence 0.5 since tactic-level matching
   * is less specific than technique-level matching.
   *
   * @param tactic - MITRE ATT&CK tactic name (e.g., 'credential-access').
   * @returns Array of MatchResult objects, one per matching technique.
   */
  matchByTactic(tactic: string): MatchResult[] {
    const normalized = tactic.toLowerCase().trim();

    return this.mappings
      .filter((m) => m.tactic.toLowerCase() === normalized)
      .map((m) => ({
        technique_id: m.technique_id,
        matched_playbooks: [...m.playbook_files],
        default_level: m.default_level,
        confidence: 0.5,
      }));
  }

  /**
   * Return all loaded technique-to-playbook mappings.
   *
   * Returns a shallow copy of the internal array. Each TechniqueMapping
   * within the array shares references with the internal state.
   */
  getMapping(): TechniqueMapping[] {
    return [...this.mappings];
  }

  /**
   * Add a new technique mapping at runtime.
   *
   * If a mapping with the same technique_id already exists, it is
   * replaced with the new one.
   *
   * @param mapping - The TechniqueMapping to add.
   */
  addMapping(mapping: TechniqueMapping): void {
    const normalized = mapping.technique_id.toUpperCase().trim();
    const existingIndex = this.mappings.findIndex(
      (m) => m.technique_id.toUpperCase() === normalized,
    );

    if (existingIndex >= 0) {
      this.mappings[existingIndex] = mapping;
    } else {
      this.mappings.push(mapping);
    }
  }

  /**
   * Get the first (default) playbook file for a given technique ID.
   *
   * Falls back to the global default_playbook from the YAML config
   * if the technique has no specific mapping.
   *
   * @param techniqueId - MITRE ATT&CK technique ID.
   * @returns The first playbook file path, or the global default, or undefined.
   */
  getDefaultPlaybook(techniqueId: string): string | undefined {
    const result = this.match(techniqueId);

    if (result && result.matched_playbooks.length > 0) {
      return result.matched_playbooks[0];
    }

    return this.defaultPlaybook;
  }

  /**
   * Get the global default playbook path from the YAML config.
   */
  getGlobalDefault(): string | undefined {
    return this.defaultPlaybook;
  }

  /**
   * Get the total number of loaded mappings.
   */
  get size(): number {
    return this.mappings.length;
  }

  // -------------------------------------------------------------------------
  // Internal Helpers
  // -------------------------------------------------------------------------

  /**
   * Parse and validate a single YAML mapping entry.
   * Returns null for invalid entries (skipped silently).
   */
  private parseEntry(entry: unknown): TechniqueMapping | null {
    if (entry === null || entry === undefined || typeof entry !== 'object') {
      return null;
    }

    const e = entry as YamlMappingEntry;

    // Required fields
    if (typeof e.technique_id !== 'string' || e.technique_id.trim().length === 0) {
      return null;
    }
    if (typeof e.technique_name !== 'string' || e.technique_name.trim().length === 0) {
      return null;
    }
    if (typeof e.tactic !== 'string' || e.tactic.trim().length === 0) {
      return null;
    }
    if (!Array.isArray(e.playbook_files) || e.playbook_files.length === 0) {
      return null;
    }

    // Validate all playbook_files are non-empty strings
    const validFiles = e.playbook_files.filter(
      (f): f is string => typeof f === 'string' && f.trim().length > 0,
    );
    if (validFiles.length === 0) {
      return null;
    }

    // Validate default_level
    const level = typeof e.default_level === 'string'
      ? e.default_level.toUpperCase().trim()
      : 'L0';

    if (!VALID_LEVELS.has(level as AutomationLevel)) {
      return null;
    }

    return {
      technique_id: e.technique_id.trim(),
      technique_name: e.technique_name.trim(),
      tactic: e.tactic.trim(),
      playbook_files: validFiles.map((f) => f.trim()),
      default_level: level as AutomationLevel,
    };
  }
}

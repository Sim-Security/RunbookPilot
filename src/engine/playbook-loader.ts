/**
 * RunbookPilot Playbook Loader
 *
 * Loads, parses, validates, and caches YAML playbook files.
 * Uses the playbook-validator for schema validation and returns
 * typed results without ever throwing exceptions.
 *
 * @module engine/playbook-loader
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { resolve, join, extname, basename } from 'path';
import { parse as parseYaml } from 'yaml';

import {
  validatePlaybookFile,
  validatePlaybookYaml,
} from '../validators/playbook-validator.ts';

import type { Runbook } from '../types/playbook.ts';
import type { ValidationResult } from '../validators/playbook-validator.ts';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Result of loading a playbook file or YAML string.
 */
export interface PlaybookLoadResult {
  success: boolean;
  playbook?: Runbook;
  errors: string[];
  filePath?: string;
}

/**
 * Lightweight playbook metadata returned by directory listing.
 * Extracted from YAML frontmatter without full schema validation.
 */
export interface PlaybookInfo {
  filePath: string;
  name: string;
  automationLevel: string;
  version: string;
}

/**
 * A successfully loaded and validated playbook stored in the cache.
 */
export interface CachedPlaybook {
  playbook: Runbook;
  loadedAt: number; // Date.now()
  filePath: string;
}

// ---------------------------------------------------------------------------
// Internal Cache
// ---------------------------------------------------------------------------

const playbookCache = new Map<string, CachedPlaybook>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load a playbook from a YAML file on disk.
 *
 * Resolves the path to an absolute path, checks the cache first,
 * validates via the playbook-validator, and caches on success.
 * Never throws -- all errors are returned in the result.
 */
export function loadPlaybook(filePath: string): PlaybookLoadResult {
  try {
    const absolutePath = resolve(filePath);

    // Check cache first
    const cached = playbookCache.get(absolutePath);
    if (cached) {
      return {
        success: true,
        playbook: cached.playbook,
        errors: [],
        filePath: absolutePath,
      };
    }

    // Validate via the existing validator
    const validationResult: ValidationResult = validatePlaybookFile(absolutePath);

    if (!validationResult.success) {
      return {
        success: false,
        errors: validationResult.errors,
        filePath: absolutePath,
      };
    }

    const playbook = validationResult.data as Runbook;

    // Cache on success
    playbookCache.set(absolutePath, {
      playbook,
      loadedAt: Date.now(),
      filePath: absolutePath,
    });

    return {
      success: true,
      playbook,
      errors: [],
      filePath: absolutePath,
    };
  } catch (error: unknown) {
    return {
      success: false,
      errors: [
        `Unexpected error loading playbook: ${error instanceof Error ? error.message : String(error)}`,
      ],
      filePath,
    };
  }
}

/**
 * Load a playbook from a raw YAML string.
 *
 * Validates the content via the playbook-validator.
 * Does not cache since there is no file path key.
 * Never throws -- all errors are returned in the result.
 */
export function loadPlaybookFromString(yamlContent: string): PlaybookLoadResult {
  try {
    const validationResult: ValidationResult = validatePlaybookYaml(yamlContent);

    if (!validationResult.success) {
      return {
        success: false,
        errors: validationResult.errors,
      };
    }

    const playbook = validationResult.data as Runbook;

    return {
      success: true,
      playbook,
      errors: [],
    };
  } catch (error: unknown) {
    return {
      success: false,
      errors: [
        `Unexpected error parsing playbook YAML: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

/**
 * List playbook files in a directory.
 *
 * Scans for .yml and .yaml files, extracts lightweight metadata
 * (name, version, automation_level) without full schema validation.
 * Skips files that cannot be read or parsed.
 * Never throws.
 */
export function listPlaybooks(directory: string): PlaybookInfo[] {
  const results: PlaybookInfo[] = [];

  try {
    const absoluteDir = resolve(directory);

    if (!existsSync(absoluteDir)) {
      return results;
    }

    const entries = readdirSync(absoluteDir);

    for (const entry of entries) {
      const ext = extname(entry).toLowerCase();
      if (ext !== '.yml' && ext !== '.yaml') {
        continue;
      }

      const fullPath = join(absoluteDir, entry);

      try {
        const content = readFileSync(fullPath, 'utf-8');
        const parsed: unknown = parseYaml(content);

        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          'runbook' in (parsed as Record<string, unknown>)
        ) {
          const wrapper = parsed as Record<string, unknown>;
          const runbook = wrapper['runbook'];

          if (runbook !== null && typeof runbook === 'object') {
            const rb = runbook as Record<string, unknown>;

            const name = extractString(rb, 'metadata', 'name') ?? basename(entry, ext);
            const version = typeof rb['version'] === 'string' ? rb['version'] : 'unknown';

            let automationLevel = 'unknown';
            if (
              rb['config'] !== null &&
              typeof rb['config'] === 'object'
            ) {
              const config = rb['config'] as Record<string, unknown>;
              if (typeof config['automation_level'] === 'string') {
                automationLevel = config['automation_level'];
              }
            }

            results.push({
              filePath: fullPath,
              name,
              automationLevel,
              version,
            });
          }
        }
      } catch {
        // Skip files that cannot be read or parsed
        continue;
      }
    }
  } catch {
    // Return empty array if directory cannot be read
  }

  return results;
}

/**
 * Get the current in-memory playbook cache.
 */
export function getPlaybookCache(): Map<string, CachedPlaybook> {
  return playbookCache;
}

/**
 * Clear the entire in-memory playbook cache.
 */
export function clearPlaybookCache(): void {
  playbookCache.clear();
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Safely extract a nested string property from an unknown object.
 * Used for lightweight metadata extraction without validation.
 */
function extractString(
  obj: Record<string, unknown>,
  outerKey: string,
  innerKey: string,
): string | undefined {
  const outer = obj[outerKey];
  if (outer !== null && typeof outer === 'object') {
    const inner = (outer as Record<string, unknown>)[innerKey];
    if (typeof inner === 'string') {
      return inner;
    }
  }
  return undefined;
}

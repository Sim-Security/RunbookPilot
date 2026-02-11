#!/usr/bin/env bun
import { Command } from 'commander';
import { readdirSync, readFileSync, existsSync } from 'fs';
import { resolve, join, extname } from 'path';
import { parse as parseYaml } from 'yaml';

import { loadPlaybook } from '../engine/playbook-loader.ts';
import { PlaybookMatcher } from '../engine/playbook-matcher.ts';

import type { Runbook, RunbookStep } from '../types/playbook.ts';

const program = new Command();

program
  .name('runbookpilot')
  .description('AI-assisted SOC runbook automation with graduated autonomy')
  .version('0.1.0');

// Global flags
program
  .option('-v, --verbose', 'Enable verbose output')
  .option('--dry-run', 'Validate and plan without executing')
  .option('--automation-level <level>', 'Override automation level (L0, L1, L2)', 'L0')
  .option('--enable-l2', 'Enable L2 simulation mode (required for L2 execution)');

// run command
program
  .command('run <playbook>')
  .description('Execute a playbook against an alert')
  .option('-i, --input <file>', 'Alert input file (JSON/ECS format)')
  .option('-a, --automation-level <level>', 'Override automation level')
  .option('--timeout <seconds>', 'Override max execution time')
  .action(async (playbook: string, options: Record<string, string>) => {
    const globalOpts = program.opts();
    if (globalOpts['verbose']) {
      console.log('Verbose mode enabled');
    }
    console.log(`Running playbook: ${playbook}`);
    console.log('Options:', { ...globalOpts, ...options });
    // Placeholder — S1 implements actual execution
    console.log('Execution engine not yet implemented (coming in S1)');
  });

// validate command
program
  .command('validate <playbook>')
  .description('Validate a playbook YAML file against the schema')
  .action(async (playbook: string) => {
    const { validatePlaybookFile } = await import('../validators/playbook-validator.ts');
    const result = validatePlaybookFile(playbook);
    if (result.success) {
      console.log(`Valid: ${playbook}`);
    } else {
      console.error(`Invalid: ${playbook}`);
      for (const error of result.errors) {
        console.error(`  - ${error}`);
      }
      process.exit(1);
    }
  });

// list command
program
  .command('list')
  .description('List available playbooks')
  .option('-f, --format <format>', 'Output format (table, json)', 'table')
  .action(async (options: Record<string, string>) => {
    console.log(`Listing playbooks (format: ${options['format']})`);
    // Placeholder — S4 implements playbook library
    console.log('Playbook library not yet implemented (coming in S4)');
  });

// ---------------------------------------------------------------------------
// show command
// ---------------------------------------------------------------------------

program
  .command('show <playbook>')
  .description('Display detailed information about a playbook')
  .option('--json', 'Output as JSON')
  .action(async (playbookPath: string, options: Record<string, unknown>) => {
    const result = loadPlaybook(playbookPath);

    if (!result.success || !result.playbook) {
      console.error(`Error: Could not load playbook: ${playbookPath}`);
      for (const error of result.errors) {
        console.error(`  - ${error}`);
      }
      process.exit(1);
    }

    const playbook: Runbook = result.playbook;

    if (options['json']) {
      console.log(JSON.stringify(playbook, null, 2));
      return;
    }

    // Human-readable output
    console.log('');
    console.log(`Playbook: ${playbook.metadata.name}`);
    console.log('='.repeat(60));
    console.log('');

    // Basic info
    console.log(`  ID:                ${playbook.id}`);
    console.log(`  Version:           ${playbook.version}`);
    if (playbook.metadata.description) {
      console.log(`  Description:       ${playbook.metadata.description.trim()}`);
    }
    if (playbook.metadata.author) {
      console.log(`  Author:            ${playbook.metadata.author}`);
    }
    console.log(`  Automation Level:  ${playbook.config.automation_level}`);
    console.log('');

    // Triggers
    console.log('  Triggers:');
    console.log(`    Detection Sources: ${playbook.triggers.detection_sources.join(', ')}`);
    console.log(`    MITRE Techniques:  ${playbook.triggers.mitre_techniques.join(', ')}`);
    console.log(`    Platforms:         ${playbook.triggers.platforms.join(', ')}`);
    if (playbook.triggers.severity && playbook.triggers.severity.length > 0) {
      console.log(`    Severity:          ${playbook.triggers.severity.join(', ')}`);
    }
    console.log('');

    // Steps
    console.log(`  Steps (${playbook.steps.length}):`)
    console.log('  ' + '-'.repeat(58));

    for (const step of playbook.steps) {
      formatStep(step);
    }
  });

/**
 * Format a single step for human-readable display.
 */
function formatStep(step: RunbookStep): void {
  console.log(`    [${step.id}] ${step.name}`);
  console.log(`      Action:       ${step.action}`);
  console.log(`      Executor:     ${step.executor}`);
  if (step.depends_on && step.depends_on.length > 0) {
    console.log(`      Dependencies: ${step.depends_on.join(', ')}`);
  }
  if (step.rollback) {
    console.log(`      Rollback:     ${step.rollback.action} (timeout: ${step.rollback.timeout}s)`);
  } else {
    console.log(`      Rollback:     none`);
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// search command
// ---------------------------------------------------------------------------

/**
 * Recursively collect all .yml and .yaml files under a directory.
 */
function collectYamlFiles(directory: string): string[] {
  const results: string[] = [];
  const absoluteDir = resolve(directory);

  if (!existsSync(absoluteDir)) {
    return results;
  }

  try {
    const entries = readdirSync(absoluteDir, { withFileTypes: true, recursive: true });
    for (const entry of entries) {
      const ext = extname(entry.name).toLowerCase();
      if ((ext === '.yml' || ext === '.yaml') && entry.isFile()) {
        // entry.parentPath is available in Node 20+ / Bun
        const parentDir = (entry as unknown as { parentPath?: string }).parentPath ?? absoluteDir;
        results.push(join(parentDir, entry.name));
      }
    }
  } catch {
    // Return empty if directory cannot be read
  }

  return results;
}

/**
 * Lightweight parsed playbook data for search purposes.
 */
interface SearchablePlaybook {
  filePath: string;
  name: string;
  description: string;
  automationLevel: string;
  tags: string[];
  mitreTechniques: string[];
}

/**
 * Parse a YAML file into lightweight search metadata.
 * Returns null if the file cannot be read or is not a valid runbook.
 */
function parseForSearch(filePath: string): SearchablePlaybook | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed: unknown = parseYaml(content);

    if (parsed === null || typeof parsed !== 'object' || !('runbook' in (parsed as Record<string, unknown>))) {
      return null;
    }

    const wrapper = parsed as Record<string, unknown>;
    const runbook = wrapper['runbook'];

    if (runbook === null || typeof runbook !== 'object') {
      return null;
    }

    const rb = runbook as Record<string, unknown>;

    // Extract metadata
    let name = '';
    let description = '';
    let tags: string[] = [];
    if (rb['metadata'] !== null && typeof rb['metadata'] === 'object') {
      const meta = rb['metadata'] as Record<string, unknown>;
      name = typeof meta['name'] === 'string' ? meta['name'] : '';
      description = typeof meta['description'] === 'string' ? meta['description'] : '';
      tags = Array.isArray(meta['tags']) ? meta['tags'].filter((t): t is string => typeof t === 'string') : [];
    }

    // Extract automation_level
    let automationLevel = 'unknown';
    if (rb['config'] !== null && typeof rb['config'] === 'object') {
      const config = rb['config'] as Record<string, unknown>;
      if (typeof config['automation_level'] === 'string') {
        automationLevel = config['automation_level'];
      }
    }

    // Extract MITRE techniques
    let mitreTechniques: string[] = [];
    if (rb['triggers'] !== null && typeof rb['triggers'] === 'object') {
      const triggers = rb['triggers'] as Record<string, unknown>;
      if (Array.isArray(triggers['mitre_techniques'])) {
        mitreTechniques = triggers['mitre_techniques'].filter((t): t is string => typeof t === 'string');
      }
    }

    return { filePath, name, description, automationLevel, tags, mitreTechniques };
  } catch {
    return null;
  }
}

program
  .command('search <term>')
  .description('Search playbooks by keyword or MITRE technique ID')
  .option('-d, --directory <dir>', 'Playbooks directory', 'playbooks')
  .action(async (term: string, options: Record<string, string>) => {
    const playbooksDir = options['directory'] ?? 'playbooks';
    const searchTerm = term.toLowerCase().trim();

    // Determine if the search term looks like a MITRE technique ID (e.g., T1566, T1566.001)
    const isTechniqueSearch = /^t\d{4}(\.\d{3})?$/i.test(searchTerm);

    // Collect results from directory scan
    const yamlFiles = collectYamlFiles(playbooksDir);
    const matches: Array<{ playbook: SearchablePlaybook; matchedOn: string }> = [];

    for (const filePath of yamlFiles) {
      const pb = parseForSearch(filePath);
      if (!pb) continue;

      // Search across name, description, tags, mitre_techniques
      const matchedFields: string[] = [];

      if (pb.name.toLowerCase().includes(searchTerm)) {
        matchedFields.push('name');
      }
      if (pb.description.toLowerCase().includes(searchTerm)) {
        matchedFields.push('description');
      }
      if (pb.tags.some((tag) => tag.toLowerCase().includes(searchTerm))) {
        matchedFields.push('tags');
      }
      if (pb.mitreTechniques.some((t) => t.toLowerCase() === searchTerm)) {
        matchedFields.push('mitre_techniques');
      }

      if (matchedFields.length > 0) {
        matches.push({ playbook: pb, matchedOn: matchedFields.join(', ') });
      }
    }

    // Additionally use PlaybookMatcher for technique-based lookup
    let matcherResults: string[] = [];
    if (isTechniqueSearch) {
      try {
        const matcher = new PlaybookMatcher();
        const techniqueMatch = matcher.match(searchTerm);
        if (techniqueMatch) {
          matcherResults = techniqueMatch.matched_playbooks;
        }
      } catch {
        // Matcher config may not exist; skip silently
      }
    }

    // Display results
    if (matches.length === 0 && matcherResults.length === 0) {
      console.log(`No playbooks found matching: ${term}`);
      process.exit(0);
    }

    console.log('');
    console.log(`Search results for: ${term}`);
    console.log('='.repeat(60));
    console.log('');

    if (matches.length > 0) {
      for (const { playbook, matchedOn } of matches) {
        console.log(`  Name:              ${playbook.name || '(unnamed)'}`);
        console.log(`  File:              ${playbook.filePath}`);
        console.log(`  Automation Level:  ${playbook.automationLevel}`);
        console.log(`  MITRE Techniques:  ${playbook.mitreTechniques.join(', ') || 'none'}`);
        console.log(`  Matched On:        ${matchedOn}`);
        console.log('');
      }
    }

    if (matcherResults.length > 0) {
      console.log('  Technique-to-Playbook Mappings:');
      for (const playbookFile of matcherResults) {
        console.log(`    - ${playbookFile}`);
      }
      console.log('');
    }

    console.log(`Found ${matches.length} playbook(s) in directory scan.`);
    if (matcherResults.length > 0) {
      console.log(`Found ${matcherResults.length} mapped playbook(s) via technique matcher.`);
    }
  });

program.parse();

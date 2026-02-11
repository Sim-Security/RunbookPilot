#!/usr/bin/env bun
import { Command } from 'commander';

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

program.parse();

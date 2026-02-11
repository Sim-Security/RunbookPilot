/**
 * Unit tests for metrics-commands CLI registration.
 *
 * These tests verify the Commander.js command tree structure registered by
 * registerMetricsCommands() — command names, descriptions, options, and
 * subcommand hierarchy. They intentionally do NOT invoke the action handlers
 * (which require DB access via dynamic imports).
 */

import { describe, it, expect } from 'vitest';
import { Command } from 'commander';
import { registerMetricsCommands } from '../../../src/cli/metrics-commands.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createProgram(): Command {
  const program = new Command();
  program.exitOverride(); // prevent process.exit in tests
  registerMetricsCommands(program);
  return program;
}

/** Find a top-level command by name on the given program. */
function findCommand(program: Command, name: string): Command | undefined {
  return program.commands.find((cmd) => cmd.name() === name);
}

/** Find a subcommand by name under a parent command. */
function findSubcommand(parent: Command, name: string): Command | undefined {
  return parent.commands.find((cmd) => cmd.name() === name);
}

/** Extract option flags from a command. */
function getOptionFlags(cmd: Command): string[] {
  return cmd.options.map((opt) => opt.flags);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('registerMetricsCommands', () => {
  // -----------------------------------------------------------------------
  // Top-level registration
  // -----------------------------------------------------------------------

  it('registers a "metrics" command on the program', () => {
    const program = createProgram();
    const metricsCmd = findCommand(program, 'metrics');
    expect(metricsCmd).toBeDefined();
  });

  it('metrics command has the correct description', () => {
    const program = createProgram();
    const metricsCmd = findCommand(program, 'metrics')!;
    expect(metricsCmd.description()).toBe('Display execution metrics dashboard');
  });

  it('registers exactly 3 subcommands under metrics', () => {
    const program = createProgram();
    const metricsCmd = findCommand(program, 'metrics')!;
    expect(metricsCmd.commands).toHaveLength(3);
  });

  it('subcommand names are summary, latency, coverage', () => {
    const program = createProgram();
    const metricsCmd = findCommand(program, 'metrics')!;
    const names = metricsCmd.commands.map((cmd) => cmd.name()).sort();
    expect(names).toEqual(['coverage', 'latency', 'summary']);
  });

  // -----------------------------------------------------------------------
  // metrics summary
  // -----------------------------------------------------------------------

  describe('metrics summary', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary');
      expect(summaryCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      expect(summaryCmd.description()).toBe('Show execution stats overview');
    });

    it('has a -p/--period option', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      const flags = getOptionFlags(summaryCmd);
      expect(flags.some((f) => f.includes('--period') && f.includes('-p'))).toBe(true);
    });

    it('--period option defaults to "7d"', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      const periodOpt = summaryCmd.options.find((o) => o.long === '--period');
      expect(periodOpt).toBeDefined();
      expect(periodOpt!.defaultValue).toBe('7d');
    });

    it('has a --json flag', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      const flags = getOptionFlags(summaryCmd);
      expect(flags.some((f) => f.includes('--json'))).toBe(true);
    });

    it('--json is a boolean flag (no value argument)', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      const jsonOpt = summaryCmd.options.find((o) => o.long === '--json');
      expect(jsonOpt).toBeDefined();
      expect(jsonOpt!.flags).not.toContain('<');
      expect(jsonOpt!.flags).not.toContain('>');
    });

    it('does not require any positional arguments', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const summaryCmd = findSubcommand(metricsCmd, 'summary')!;
      const args = (summaryCmd as unknown as { registeredArguments: unknown[] }).registeredArguments ?? [];
      expect(args).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // metrics latency
  // -----------------------------------------------------------------------

  describe('metrics latency', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const latencyCmd = findSubcommand(metricsCmd, 'latency');
      expect(latencyCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const latencyCmd = findSubcommand(metricsCmd, 'latency')!;
      expect(latencyCmd.description()).toBe('Show approval latency metrics');
    });

    it('has a -p/--period option', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const latencyCmd = findSubcommand(metricsCmd, 'latency')!;
      const flags = getOptionFlags(latencyCmd);
      expect(flags.some((f) => f.includes('--period') && f.includes('-p'))).toBe(true);
    });

    it('--period option defaults to "7d"', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const latencyCmd = findSubcommand(metricsCmd, 'latency')!;
      const periodOpt = latencyCmd.options.find((o) => o.long === '--period');
      expect(periodOpt).toBeDefined();
      expect(periodOpt!.defaultValue).toBe('7d');
    });

    it('has a --json flag', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const latencyCmd = findSubcommand(metricsCmd, 'latency')!;
      const flags = getOptionFlags(latencyCmd);
      expect(flags.some((f) => f.includes('--json'))).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // metrics coverage
  // -----------------------------------------------------------------------

  describe('metrics coverage', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const coverageCmd = findSubcommand(metricsCmd, 'coverage');
      expect(coverageCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const coverageCmd = findSubcommand(metricsCmd, 'coverage')!;
      expect(coverageCmd.description()).toBe(
        'Show playbook coverage for ATT&CK techniques',
      );
    });

    it('has a -p/--period option', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const coverageCmd = findSubcommand(metricsCmd, 'coverage')!;
      const flags = getOptionFlags(coverageCmd);
      expect(flags.some((f) => f.includes('--period') && f.includes('-p'))).toBe(true);
    });

    it('--period option defaults to "30d"', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const coverageCmd = findSubcommand(metricsCmd, 'coverage')!;
      const periodOpt = coverageCmd.options.find((o) => o.long === '--period');
      expect(periodOpt).toBeDefined();
      expect(periodOpt!.defaultValue).toBe('30d');
    });

    it('has a --json flag', () => {
      const program = createProgram();
      const metricsCmd = findCommand(program, 'metrics')!;
      const coverageCmd = findSubcommand(metricsCmd, 'coverage')!;
      const flags = getOptionFlags(coverageCmd);
      expect(flags.some((f) => f.includes('--json'))).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Idempotency / isolation
  // -----------------------------------------------------------------------

  it('does not modify other commands on the program', () => {
    const program = new Command();
    program.command('existing').description('Pre-existing command');
    registerMetricsCommands(program);

    const names = program.commands.map((cmd) => cmd.name());
    expect(names).toContain('existing');
    expect(names).toContain('metrics');
    expect(program.commands).toHaveLength(2);
  });

  it('can be registered on a fresh program without throwing', () => {
    expect(() => {
      const program = new Command();
      registerMetricsCommands(program);
    }).not.toThrow();
  });
});

/**
 * Unit tests for queue-commands CLI registration.
 *
 * These tests verify the Commander.js command tree structure registered by
 * registerQueueCommands() — command names, descriptions, arguments, options,
 * and subcommand hierarchy. They intentionally do NOT invoke the action
 * handlers (which require DB access).
 */

import { describe, it, expect } from 'vitest';
import { Command } from 'commander';
import { registerQueueCommands } from '../../../src/cli/queue-commands.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createProgram(): Command {
  const program = new Command();
  program.exitOverride(); // prevent process.exit in tests
  registerQueueCommands(program);
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

/** Extract option flags from a command (e.g. ['--status <status>', '--limit <n>']). */
function getOptionFlags(cmd: Command): string[] {
  return cmd.options.map((opt) => opt.flags);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('registerQueueCommands', () => {
  // -----------------------------------------------------------------------
  // Top-level registration
  // -----------------------------------------------------------------------

  it('registers a "queue" command on the program', () => {
    const program = createProgram();
    const queueCmd = findCommand(program, 'queue');
    expect(queueCmd).toBeDefined();
  });

  it('queue command has the correct description', () => {
    const program = createProgram();
    const queueCmd = findCommand(program, 'queue')!;
    expect(queueCmd.description()).toBe('Manage the L2 approval queue');
  });

  it('registers exactly 5 subcommands under queue', () => {
    const program = createProgram();
    const queueCmd = findCommand(program, 'queue')!;
    expect(queueCmd.commands).toHaveLength(5);
  });

  it('subcommand names are list, approve, deny, inspect, expire', () => {
    const program = createProgram();
    const queueCmd = findCommand(program, 'queue')!;
    const names = queueCmd.commands.map((cmd) => cmd.name()).sort();
    expect(names).toEqual(['approve', 'deny', 'expire', 'inspect', 'list']);
  });

  // -----------------------------------------------------------------------
  // queue list
  // -----------------------------------------------------------------------

  describe('queue list', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list');
      expect(listCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      expect(listCmd.description()).toBe('List approval queue entries');
    });

    it('has a --status option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const flags = getOptionFlags(listCmd);
      expect(flags.some((f) => f.includes('--status'))).toBe(true);
    });

    it('--status option defaults to "pending"', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const statusOpt = listCmd.options.find((o) => o.long === '--status');
      expect(statusOpt).toBeDefined();
      expect(statusOpt!.defaultValue).toBe('pending');
    });

    it('has a --limit option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const flags = getOptionFlags(listCmd);
      expect(flags.some((f) => f.includes('--limit'))).toBe(true);
    });

    it('--limit option defaults to "50"', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const limitOpt = listCmd.options.find((o) => o.long === '--limit');
      expect(limitOpt).toBeDefined();
      expect(limitOpt!.defaultValue).toBe('50');
    });

    it('has a --format option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const flags = getOptionFlags(listCmd);
      expect(flags.some((f) => f.includes('--format'))).toBe(true);
    });

    it('--format option defaults to "table"', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      const formatOpt = listCmd.options.find((o) => o.long === '--format');
      expect(formatOpt).toBeDefined();
      expect(formatOpt!.defaultValue).toBe('table');
    });

    it('does not require any positional arguments', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const listCmd = findSubcommand(queueCmd, 'list')!;
      // Commander stores registered args on .registeredArguments or ._args
      const args = (listCmd as unknown as { registeredArguments: unknown[] }).registeredArguments ?? [];
      expect(args).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // queue approve
  // -----------------------------------------------------------------------

  describe('queue approve', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const approveCmd = findSubcommand(queueCmd, 'approve');
      expect(approveCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const approveCmd = findSubcommand(queueCmd, 'approve')!;
      expect(approveCmd.description()).toBe('Approve a pending approval request');
    });

    it('requires a <request-id> argument', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const approveCmd = findSubcommand(queueCmd, 'approve')!;
      const args = (approveCmd as unknown as { registeredArguments: Array<{ _name: string; required: boolean }> }).registeredArguments ?? [];
      expect(args.length).toBeGreaterThanOrEqual(1);
      expect(args[0]!._name).toBe('request-id');
      expect(args[0]!.required).toBe(true);
    });

    it('has an --approver option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const approveCmd = findSubcommand(queueCmd, 'approve')!;
      const flags = getOptionFlags(approveCmd);
      expect(flags.some((f) => f.includes('--approver'))).toBe(true);
    });

    it('--approver option has a default value', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const approveCmd = findSubcommand(queueCmd, 'approve')!;
      const approverOpt = approveCmd.options.find((o) => o.long === '--approver');
      expect(approverOpt).toBeDefined();
      // Default is process.env['USER'] || 'cli-user'; either way it should be a string
      expect(typeof approverOpt!.defaultValue).toBe('string');
    });
  });

  // -----------------------------------------------------------------------
  // queue deny
  // -----------------------------------------------------------------------

  describe('queue deny', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const denyCmd = findSubcommand(queueCmd, 'deny');
      expect(denyCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const denyCmd = findSubcommand(queueCmd, 'deny')!;
      expect(denyCmd.description()).toBe('Deny a pending approval request');
    });

    it('requires a <request-id> argument', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const denyCmd = findSubcommand(queueCmd, 'deny')!;
      const args = (denyCmd as unknown as { registeredArguments: Array<{ _name: string; required: boolean }> }).registeredArguments ?? [];
      expect(args.length).toBeGreaterThanOrEqual(1);
      expect(args[0]!._name).toBe('request-id');
      expect(args[0]!.required).toBe(true);
    });

    it('has a required --reason option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const denyCmd = findSubcommand(queueCmd, 'deny')!;
      const reasonOpt = denyCmd.options.find((o) => o.long === '--reason');
      expect(reasonOpt).toBeDefined();
      expect(reasonOpt!.required).toBe(true);
    });

    it('--reason option expects a value argument', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const denyCmd = findSubcommand(queueCmd, 'deny')!;
      const reasonOpt = denyCmd.options.find((o) => o.long === '--reason');
      expect(reasonOpt).toBeDefined();
      // A required option with an expected arg will have flags containing <reason>
      expect(reasonOpt!.flags).toContain('<reason>');
    });
  });

  // -----------------------------------------------------------------------
  // queue inspect
  // -----------------------------------------------------------------------

  describe('queue inspect', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const inspectCmd = findSubcommand(queueCmd, 'inspect');
      expect(inspectCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const inspectCmd = findSubcommand(queueCmd, 'inspect')!;
      expect(inspectCmd.description()).toBe('Show full details of a queue entry');
    });

    it('requires a <request-id> argument', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const inspectCmd = findSubcommand(queueCmd, 'inspect')!;
      const args = (inspectCmd as unknown as { registeredArguments: Array<{ _name: string; required: boolean }> }).registeredArguments ?? [];
      expect(args.length).toBeGreaterThanOrEqual(1);
      expect(args[0]!._name).toBe('request-id');
      expect(args[0]!.required).toBe(true);
    });

    it('has a --json flag option', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const inspectCmd = findSubcommand(queueCmd, 'inspect')!;
      const flags = getOptionFlags(inspectCmd);
      expect(flags.some((f) => f.includes('--json'))).toBe(true);
    });

    it('--json is a boolean flag (no value argument)', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const inspectCmd = findSubcommand(queueCmd, 'inspect')!;
      const jsonOpt = inspectCmd.options.find((o) => o.long === '--json');
      expect(jsonOpt).toBeDefined();
      // Boolean flags do not contain angle brackets in their flags string
      expect(jsonOpt!.flags).not.toContain('<');
      expect(jsonOpt!.flags).not.toContain('>');
    });
  });

  // -----------------------------------------------------------------------
  // queue expire
  // -----------------------------------------------------------------------

  describe('queue expire', () => {
    it('exists as a subcommand', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const expireCmd = findSubcommand(queueCmd, 'expire');
      expect(expireCmd).toBeDefined();
    });

    it('has the correct description', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const expireCmd = findSubcommand(queueCmd, 'expire')!;
      expect(expireCmd.description()).toBe(
        'Expire all stale entries past their expires_at',
      );
    });

    it('does not require any positional arguments', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const expireCmd = findSubcommand(queueCmd, 'expire')!;
      const args = (expireCmd as unknown as { registeredArguments: unknown[] }).registeredArguments ?? [];
      expect(args).toHaveLength(0);
    });

    it('has no options', () => {
      const program = createProgram();
      const queueCmd = findCommand(program, 'queue')!;
      const expireCmd = findSubcommand(queueCmd, 'expire')!;
      expect(expireCmd.options).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Idempotency / isolation
  // -----------------------------------------------------------------------

  it('does not modify other commands on the program', () => {
    const program = new Command();
    program.command('existing').description('Pre-existing command');
    registerQueueCommands(program);

    const names = program.commands.map((cmd) => cmd.name());
    expect(names).toContain('existing');
    expect(names).toContain('queue');
    expect(program.commands).toHaveLength(2);
  });

  it('can be registered on a fresh program without throwing', () => {
    expect(() => {
      const program = new Command();
      registerQueueCommands(program);
    }).not.toThrow();
  });
});

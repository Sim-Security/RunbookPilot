import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';

const CLI = 'bun run src/cli/index.ts';

function runCli(args: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execSync(`${CLI} ${args}`, {
      cwd: process.cwd(),
      encoding: 'utf-8',
      timeout: 10000,
    });
    return { stdout, exitCode: 0 };
  } catch (error: unknown) {
    const execError = error as { stdout?: string; status?: number };
    return {
      stdout: execError.stdout ?? '',
      exitCode: execError.status ?? 1,
    };
  }
}

describe('CLI', () => {
  it('displays help text', () => {
    const result = runCli('--help');
    expect(result.stdout).toContain('runbookpilot');
    expect(result.stdout).toContain('run');
    expect(result.stdout).toContain('validate');
    expect(result.stdout).toContain('list');
  });

  it('displays version', () => {
    const result = runCli('--version');
    expect(result.stdout.trim()).toBe('0.1.0');
  });

  it('shows help for run command', () => {
    const result = runCli('run --help');
    expect(result.stdout).toContain('playbook');
    expect(result.stdout).toContain('--input');
  });

  it('shows help for validate command', () => {
    const result = runCli('validate --help');
    expect(result.stdout).toContain('playbook');
  });

  it('shows help for list command', () => {
    const result = runCli('list --help');
    expect(result.stdout).toContain('--format');
  });

  it('supports global flags', () => {
    const result = runCli('--help');
    expect(result.stdout).toContain('--verbose');
    expect(result.stdout).toContain('--dry-run');
    expect(result.stdout).toContain('--automation-level');
    expect(result.stdout).toContain('--enable-l2');
  });
});

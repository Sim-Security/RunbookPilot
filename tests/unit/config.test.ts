import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadConfig, getConfig, redactSecrets, resetConfig } from '../../src/config/index.ts';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a temporary directory for test config files. */
function makeTempDir(): string {
  const dir = join(tmpdir(), `rbp-config-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Configuration System', () => {
  beforeEach(() => {
    // Reset cached config before each test
    resetConfig();

    // Stub all env vars to empty so defaults are used unless a test overrides
    vi.stubEnv('LOG_LEVEL', '');
    vi.stubEnv('RUNBOOKPILOT_DB_PATH', '');
    vi.stubEnv('PLAYBOOK_DIRS', '');
    vi.stubEnv('ADAPTER_DIRS', '');
    vi.stubEnv('AUTOMATION_LEVEL', '');
    vi.stubEnv('OPENROUTER_BASE_URL', '');
    vi.stubEnv('OPENROUTER_API_KEY', '');
    vi.stubEnv('OPENROUTER_MODEL_FAST', '');
    vi.stubEnv('OPENROUTER_MODEL_STANDARD', '');
    vi.stubEnv('OPENROUTER_MODEL_QUALITY', '');
    vi.stubEnv('OPENROUTER_TIMEOUT', '');
    vi.stubEnv('OPENROUTER_MAX_TOKENS', '');
    vi.stubEnv('OPENROUTER_TEMPERATURE', '');
    vi.stubEnv('OPENROUTER_RETRIES', '');
    vi.stubEnv('SERVER_PORT', '');
    vi.stubEnv('SERVER_HOST', '');
    vi.stubEnv('APPROVAL_TIMEOUT', '');
    vi.stubEnv('MAX_EXECUTION_TIME', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    resetConfig();
  });

  // -------------------------------------------------------------------------
  // Default configuration
  // -------------------------------------------------------------------------

  describe('loadConfig() with defaults', () => {
    it('loads default config when no env vars are set', () => {
      const config = loadConfig();

      expect(config.logLevel).toBe('info');
      expect(config.dbPath).toBe('./data/runbookpilot.db');
      expect(config.playbookDirs).toEqual(['./playbooks']);
      expect(config.adapterDirs).toEqual(['./adapters']);
      expect(config.automationLevel).toBe('L0');

      // OpenRouter defaults
      expect(config.openRouter.baseUrl).toBe('https://openrouter.ai/api/v1');
      expect(config.openRouter.apiKey).toBe('');
      expect(config.openRouter.models.fast).toBe('openai/gpt-4o-mini');
      expect(config.openRouter.models.standard).toBe('anthropic/claude-3.5-sonnet');
      expect(config.openRouter.models.quality).toBe('anthropic/claude-3-opus');
      expect(config.openRouter.timeout).toBe(30_000);
      expect(config.openRouter.maxTokens).toBe(200_000);
      expect(config.openRouter.temperature).toBe(0.1);
      expect(config.openRouter.retries).toBe(3);

      // Server defaults
      expect(config.server.port).toBe(3000);
      expect(config.server.host).toBe('0.0.0.0');

      // Timeout defaults
      expect(config.approvalTimeout).toBe(3600);
      expect(config.maxExecutionTime).toBe(900);
    });
  });

  // -------------------------------------------------------------------------
  // Environment variable overrides
  // -------------------------------------------------------------------------

  describe('loadConfig() with environment variables', () => {
    it('loads config from environment variables', () => {
      vi.stubEnv('LOG_LEVEL', 'debug');
      vi.stubEnv('RUNBOOKPILOT_DB_PATH', '/tmp/test.db');
      vi.stubEnv('PLAYBOOK_DIRS', '/opt/playbooks,/etc/runbooks');
      vi.stubEnv('ADAPTER_DIRS', '/opt/adapters');
      vi.stubEnv('AUTOMATION_LEVEL', 'L1');
      vi.stubEnv('OPENROUTER_BASE_URL', 'https://custom.api.example.com/v1');
      vi.stubEnv('OPENROUTER_API_KEY', 'sk-or-test-key-12345');
      vi.stubEnv('OPENROUTER_MODEL_FAST', 'openai/gpt-4o');
      vi.stubEnv('OPENROUTER_MODEL_STANDARD', 'anthropic/claude-3-haiku');
      vi.stubEnv('OPENROUTER_MODEL_QUALITY', 'anthropic/claude-3.5-sonnet');
      vi.stubEnv('OPENROUTER_TIMEOUT', '60000');
      vi.stubEnv('OPENROUTER_MAX_TOKENS', '8192');
      vi.stubEnv('OPENROUTER_TEMPERATURE', '0.5');
      vi.stubEnv('OPENROUTER_RETRIES', '5');
      vi.stubEnv('SERVER_PORT', '8080');
      vi.stubEnv('SERVER_HOST', '127.0.0.1');
      vi.stubEnv('APPROVAL_TIMEOUT', '7200');
      vi.stubEnv('MAX_EXECUTION_TIME', '1800');

      const config = loadConfig();

      expect(config.logLevel).toBe('debug');
      expect(config.dbPath).toBe('/tmp/test.db');
      expect(config.playbookDirs).toEqual(['/opt/playbooks', '/etc/runbooks']);
      expect(config.adapterDirs).toEqual(['/opt/adapters']);
      expect(config.automationLevel).toBe('L1');

      expect(config.openRouter.baseUrl).toBe('https://custom.api.example.com/v1');
      expect(config.openRouter.apiKey).toBe('sk-or-test-key-12345');
      expect(config.openRouter.models.fast).toBe('openai/gpt-4o');
      expect(config.openRouter.models.standard).toBe('anthropic/claude-3-haiku');
      expect(config.openRouter.models.quality).toBe('anthropic/claude-3.5-sonnet');
      expect(config.openRouter.timeout).toBe(60000);
      expect(config.openRouter.maxTokens).toBe(8192);
      expect(config.openRouter.temperature).toBe(0.5);
      expect(config.openRouter.retries).toBe(5);

      expect(config.server.port).toBe(8080);
      expect(config.server.host).toBe('127.0.0.1');
      expect(config.approvalTimeout).toBe(7200);
      expect(config.maxExecutionTime).toBe(1800);
    });

    it('parses comma-separated playbook directories correctly', () => {
      vi.stubEnv('PLAYBOOK_DIRS', ' /a , /b , /c ');
      const config = loadConfig();
      expect(config.playbookDirs).toEqual(['/a', '/b', '/c']);
    });

    it('parses comma-separated adapter directories correctly', () => {
      vi.stubEnv('ADAPTER_DIRS', '/x,/y');
      const config = loadConfig();
      expect(config.adapterDirs).toEqual(['/x', '/y']);
    });
  });

  // -------------------------------------------------------------------------
  // YAML config file
  // -------------------------------------------------------------------------

  describe('loadConfig() with config.yml', () => {
    let tempDir: string;

    afterEach(() => {
      if (tempDir) {
        rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('loads config from a YAML file', () => {
      tempDir = makeTempDir();
      const configPath = join(tempDir, 'config.yml');

      const yamlContent = `
log_level: warn
db_path: /var/lib/rbp/data.db
playbook_dirs:
  - /etc/playbooks
  - /opt/playbooks
adapter_dirs:
  - /etc/adapters
automation_level: L2
openrouter:
  base_url: https://yaml.api.example.com/v1
  api_key: sk-yaml-key
  models:
    fast: yaml/fast-model
    standard: yaml/standard-model
    quality: yaml/quality-model
  timeout: 45000
  max_tokens: 2048
  temperature: 0.3
  retries: 2
server:
  port: 9090
  host: 192.168.1.1
approval_timeout: 1800
max_execution_time: 600
`;
      writeFileSync(configPath, yamlContent, 'utf-8');

      const config = loadConfig(configPath);

      expect(config.logLevel).toBe('warn');
      expect(config.dbPath).toBe('/var/lib/rbp/data.db');
      expect(config.playbookDirs).toEqual(['/etc/playbooks', '/opt/playbooks']);
      expect(config.adapterDirs).toEqual(['/etc/adapters']);
      expect(config.automationLevel).toBe('L2');
      expect(config.openRouter.baseUrl).toBe('https://yaml.api.example.com/v1');
      expect(config.openRouter.apiKey).toBe('sk-yaml-key');
      expect(config.openRouter.models.fast).toBe('yaml/fast-model');
      expect(config.openRouter.timeout).toBe(45000);
      expect(config.server.port).toBe(9090);
      expect(config.server.host).toBe('192.168.1.1');
      expect(config.approvalTimeout).toBe(1800);
      expect(config.maxExecutionTime).toBe(600);
    });

    it('env vars override YAML config values', () => {
      tempDir = makeTempDir();
      const configPath = join(tempDir, 'config.yml');

      const yamlContent = `
log_level: warn
automation_level: L2
server:
  port: 9090
`;
      writeFileSync(configPath, yamlContent, 'utf-8');

      vi.stubEnv('LOG_LEVEL', 'error');
      vi.stubEnv('AUTOMATION_LEVEL', 'L1');
      vi.stubEnv('SERVER_PORT', '4000');

      const config = loadConfig(configPath);

      expect(config.logLevel).toBe('error');
      expect(config.automationLevel).toBe('L1');
      expect(config.server.port).toBe(4000);
    });

    it('handles nonexistent config file path gracefully', () => {
      const config = loadConfig('/nonexistent/path/config.yml');

      // Should fall through to defaults
      expect(config.logLevel).toBe('info');
      expect(config.automationLevel).toBe('L0');
    });
  });

  // -------------------------------------------------------------------------
  // Secret redaction
  // -------------------------------------------------------------------------

  describe('redactSecrets()', () => {
    it('redacts secrets properly', () => {
      vi.stubEnv('OPENROUTER_API_KEY', 'sk-or-secret-key-12345');
      const config = loadConfig();
      const redacted = redactSecrets(config);

      // API key must be redacted
      const openRouter = redacted['openRouter'] as Record<string, unknown>;
      expect(openRouter['apiKey']).toBe('***');

      // Non-secret values should be preserved
      expect(redacted['logLevel']).toBe('info');
      expect(redacted['automationLevel']).toBe('L0');
      expect(openRouter['baseUrl']).toBe('https://openrouter.ai/api/v1');
    });

    it('shows empty string for empty API key', () => {
      const config = loadConfig();
      const redacted = redactSecrets(config);

      const openRouter = redacted['openRouter'] as Record<string, unknown>;
      expect(openRouter['apiKey']).toBe('');
    });

    it('does not mutate the original config object', () => {
      vi.stubEnv('OPENROUTER_API_KEY', 'sk-or-secret-12345');
      const config = loadConfig();
      redactSecrets(config);

      // Original should still have the real key
      expect(config.openRouter.apiKey).toBe('sk-or-secret-12345');
    });
  });

  // -------------------------------------------------------------------------
  // Validation errors
  // -------------------------------------------------------------------------

  describe('validation', () => {
    it('throws on invalid automation level', () => {
      vi.stubEnv('AUTOMATION_LEVEL', 'L5');

      expect(() => loadConfig()).toThrowError(/Invalid automation level "L5"/);
    });

    it('throws on invalid log level', () => {
      vi.stubEnv('LOG_LEVEL', 'verbose');

      expect(() => loadConfig()).toThrowError(/Invalid log level "verbose"/);
    });

    it('throws on invalid server port', () => {
      vi.stubEnv('SERVER_PORT', '99999');

      expect(() => loadConfig()).toThrowError(/Invalid server port 99999/);
    });

    it('throws on negative timeout values', () => {
      vi.stubEnv('OPENROUTER_TIMEOUT', '-1');

      expect(() => loadConfig()).toThrowError(/Invalid OpenRouter timeout/);
    });

    it('throws on out-of-range temperature', () => {
      vi.stubEnv('OPENROUTER_TEMPERATURE', '3.0');

      expect(() => loadConfig()).toThrowError(/Invalid OpenRouter temperature/);
    });
  });

  // -------------------------------------------------------------------------
  // getConfig() caching
  // -------------------------------------------------------------------------

  describe('getConfig()', () => {
    it('throws if loadConfig has not been called', () => {
      expect(() => getConfig()).toThrowError(
        /Configuration has not been loaded/,
      );
    });

    it('returns the cached config after loadConfig', () => {
      const loaded = loadConfig();
      const cached = getConfig();
      expect(cached).toBe(loaded);
    });

    it('returns updated config after reloading', () => {
      loadConfig();
      const first = getConfig();
      expect(first.logLevel).toBe('info');

      vi.stubEnv('LOG_LEVEL', 'debug');
      loadConfig();
      const second = getConfig();
      expect(second.logLevel).toBe('debug');
    });
  });

  // -------------------------------------------------------------------------
  // Edge cases / missing optional config
  // -------------------------------------------------------------------------

  describe('handles missing optional config gracefully', () => {
    it('uses default models when not specified', () => {
      const config = loadConfig();
      expect(config.openRouter.models.fast).toBe('openai/gpt-4o-mini');
      expect(config.openRouter.models.standard).toBe('anthropic/claude-3.5-sonnet');
      expect(config.openRouter.models.quality).toBe('anthropic/claude-3-opus');
    });

    it('uses default API key (empty) when not set', () => {
      const config = loadConfig();
      expect(config.openRouter.apiKey).toBe('');
    });

    it('ignores unparseable numeric env vars and falls through to defaults', () => {
      vi.stubEnv('SERVER_PORT', 'not-a-number');
      const config = loadConfig();
      expect(config.server.port).toBe(3000);
    });

    it('handles empty PLAYBOOK_DIRS string gracefully by using default', () => {
      // An empty string after stubbing is handled by the empty-check:
      // parseCommaSeparated('') returns [] but env['PLAYBOOK_DIRS'] is ''
      // which is falsy, so the default kicks in.
      // Explicitly unsetting so the env check falls through.
      vi.stubEnv('PLAYBOOK_DIRS', '');
      const config = loadConfig();
      expect(config.playbookDirs).toEqual(['./playbooks']);
    });

    it('loads config without config path', () => {
      const config = loadConfig();
      expect(config).toBeDefined();
      expect(config.logLevel).toBe('info');
    });

    it('partial YAML config merges with defaults', () => {
      const tempDir = makeTempDir();
      const configPath = join(tempDir, 'partial.yml');

      writeFileSync(configPath, 'log_level: debug\n', 'utf-8');

      const config = loadConfig(configPath);
      expect(config.logLevel).toBe('debug');
      // Everything else should be defaults
      expect(config.dbPath).toBe('./data/runbookpilot.db');
      expect(config.automationLevel).toBe('L0');
      expect(config.server.port).toBe(3000);

      rmSync(tempDir, { recursive: true, force: true });
    });
  });
});

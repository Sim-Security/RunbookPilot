import { describe, it, expect } from 'vitest';
import {
  parseAdapterConfig,
  applyEnvOverrides,
  loadAdapterConfigs,
  redactAdapterConfig,
  AdapterConfigError,
} from '../../../src/adapters/adapter-config.ts';
import type {
  RawAdapterConfigBlock,
  AdaptersConfigSection,
} from '../../../src/adapters/adapter-config.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRawBlock(overrides: Partial<RawAdapterConfigBlock> = {}): RawAdapterConfigBlock {
  return {
    name: 'crowdstrike',
    type: 'edr',
    ...overrides,
  };
}

function makeParsedConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return {
    name: 'crowdstrike',
    type: 'edr',
    enabled: true,
    config: {},
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// parseAdapterConfig
// ---------------------------------------------------------------------------

describe('parseAdapterConfig()', () => {
  it('parses a valid config block correctly', () => {
    const raw = makeRawBlock({
      enabled: false,
      timeout: 60,
      config: { base_url: 'https://api.example.com' },
      retry: { max_attempts: 5, backoff_ms: 2000, exponential: false },
    });

    const result = parseAdapterConfig('crowdstrike', raw);

    expect(result.name).toBe('crowdstrike');
    expect(result.type).toBe('edr');
    expect(result.enabled).toBe(false);
    expect(result.timeout).toBe(60);
    expect(result.config).toEqual({ base_url: 'https://api.example.com' });
    expect(result.retry).toEqual({
      max_attempts: 5,
      backoff_ms: 2000,
      exponential: false,
    });
  });

  it('uses defaults for missing optional fields', () => {
    const raw = makeRawBlock();
    const result = parseAdapterConfig('crowdstrike', raw);

    expect(result.enabled).toBe(true);
    expect(result.timeout).toBe(30);
    expect(result.config).toEqual({});
    expect(result.credentials).toBeUndefined();
    expect(result.retry).toEqual({
      max_attempts: 3,
      backoff_ms: 1000,
      exponential: true,
    });
  });

  it('throws AdapterConfigError for missing type', () => {
    const raw = makeRawBlock({ type: '' });

    expect(() => parseAdapterConfig('bad-adapter', raw)).toThrow(AdapterConfigError);

    try {
      parseAdapterConfig('bad-adapter', raw);
    } catch (err) {
      expect(err).toBeInstanceOf(AdapterConfigError);
      if (err instanceof AdapterConfigError) {
        expect(err.adapterName).toBe('bad-adapter');
        expect(err.errors.length).toBeGreaterThan(0);
        expect(err.errors.some((e) => e.includes("missing or invalid 'type'"))).toBe(true);
      }
    }
  });

  it('throws AdapterConfigError for invalid type', () => {
    const raw = makeRawBlock({ type: 'invalid_type' });

    expect(() => parseAdapterConfig('bad-adapter', raw)).toThrow(AdapterConfigError);

    try {
      parseAdapterConfig('bad-adapter', raw);
    } catch (err) {
      if (err instanceof AdapterConfigError) {
        expect(err.errors.some((e) => e.includes("invalid type 'invalid_type'"))).toBe(true);
      }
    }
  });

  it('throws AdapterConfigError for negative timeout', () => {
    const raw = makeRawBlock({ timeout: -10 });

    expect(() => parseAdapterConfig('bad-adapter', raw)).toThrow(AdapterConfigError);

    try {
      parseAdapterConfig('bad-adapter', raw);
    } catch (err) {
      if (err instanceof AdapterConfigError) {
        expect(err.errors.some((e) => e.includes('timeout must be a positive number'))).toBe(true);
      }
    }
  });

  it('throws AdapterConfigError for zero timeout', () => {
    const raw = makeRawBlock({ timeout: 0 });

    expect(() => parseAdapterConfig('bad-adapter', raw)).toThrow(AdapterConfigError);
  });

  it('throws AdapterConfigError for invalid retry config', () => {
    const raw = makeRawBlock({
      retry: { max_attempts: 0, backoff_ms: -1 },
    });

    expect(() => parseAdapterConfig('bad-adapter', raw)).toThrow(AdapterConfigError);

    try {
      parseAdapterConfig('bad-adapter', raw);
    } catch (err) {
      if (err instanceof AdapterConfigError) {
        expect(err.errors.some((e) => e.includes('retry.max_attempts must be >= 1'))).toBe(true);
        expect(err.errors.some((e) => e.includes('retry.backoff_ms must be >= 0'))).toBe(true);
      }
    }
  });

  it('parses credentials correctly', () => {
    const raw = makeRawBlock({
      credentials: {
        type: 'api_key',
        api_key: 'my-secret-key',
        client_id: 'my-client-id',
      },
    });

    const result = parseAdapterConfig('crowdstrike', raw);

    expect(result.credentials).toBeDefined();
    expect(result.credentials?.type).toBe('api_key');
    expect(result.credentials?.credentials).toEqual({
      api_key: 'my-secret-key',
      client_id: 'my-client-id',
    });
  });

  it('ignores credentials without a type field', () => {
    const raw = makeRawBlock({
      credentials: { api_key: 'my-key' },
    });

    const result = parseAdapterConfig('crowdstrike', raw);
    expect(result.credentials).toBeUndefined();
  });

  it('uses default retry values when only partial retry is specified', () => {
    const raw = makeRawBlock({
      retry: { max_attempts: 5 },
    });

    const result = parseAdapterConfig('crowdstrike', raw);

    expect(result.retry).toEqual({
      max_attempts: 5,
      backoff_ms: 1000,
      exponential: true,
    });
  });

  it('accepts all valid adapter types', () => {
    const validTypes = ['edr', 'siem', 'firewall', 'iam', 'ticketing', 'notification', 'enrichment', 'mock', 'generic'];

    for (const type of validTypes) {
      const raw = makeRawBlock({ type });
      const result = parseAdapterConfig('test', raw);
      expect(result.type).toBe(type);
    }
  });
});

// ---------------------------------------------------------------------------
// applyEnvOverrides
// ---------------------------------------------------------------------------

describe('applyEnvOverrides()', () => {
  it('applies ADAPTER_NAME_ENABLED override', () => {
    const config = makeParsedConfig({ enabled: true });
    const env = { ADAPTER_CROWDSTRIKE_ENABLED: 'false' };

    const result = applyEnvOverrides(config, env);

    expect(result.enabled).toBe(false);
  });

  it('applies ADAPTER_NAME_ENABLED as true', () => {
    const config = makeParsedConfig({ enabled: false });
    const env = { ADAPTER_CROWDSTRIKE_ENABLED: 'true' };

    const result = applyEnvOverrides(config, env);

    expect(result.enabled).toBe(true);
  });

  it('applies ADAPTER_NAME_TIMEOUT override', () => {
    const config = makeParsedConfig({ timeout: 30 });
    const env = { ADAPTER_CROWDSTRIKE_TIMEOUT: '120' };

    const result = applyEnvOverrides(config, env);

    expect(result.timeout).toBe(120);
  });

  it('applies ADAPTER_NAME_API_KEY override', () => {
    const config = makeParsedConfig();
    const env = { ADAPTER_CROWDSTRIKE_API_KEY: 'env-secret-key' };

    const result = applyEnvOverrides(config, env);

    expect(result.credentials).toBeDefined();
    expect(result.credentials?.type).toBe('api_key');
    expect(result.credentials?.credentials.api_key).toBe('env-secret-key');
  });

  it('preserves existing credential type when applying API_KEY', () => {
    const config = makeParsedConfig({
      credentials: {
        type: 'oauth2',
        credentials: { client_id: 'abc' },
      },
    });
    const env = { ADAPTER_CROWDSTRIKE_API_KEY: 'new-key' };

    const result = applyEnvOverrides(config, env);

    expect(result.credentials?.type).toBe('oauth2');
    expect(result.credentials?.credentials.api_key).toBe('new-key');
    expect(result.credentials?.credentials.client_id).toBe('abc');
  });

  it('applies ADAPTER_NAME_API_URL override', () => {
    const config = makeParsedConfig();
    const env = { ADAPTER_CROWDSTRIKE_API_URL: 'https://custom.api.com' };

    const result = applyEnvOverrides(config, env);

    expect(result.config.base_url).toBe('https://custom.api.com');
  });

  it('applies generic config keys as lowercase', () => {
    const config = makeParsedConfig();
    const env = { ADAPTER_CROWDSTRIKE_REGION: 'us-west-2' };

    const result = applyEnvOverrides(config, env);

    expect(result.config.region).toBe('us-west-2');
  });

  it('does not apply unrelated env vars', () => {
    const config = makeParsedConfig();
    const env = {
      ADAPTER_SENTINELONE_API_KEY: 'wrong-adapter',
      UNRELATED_VAR: 'irrelevant',
      PATH: '/usr/bin',
    };

    const result = applyEnvOverrides(config, env);

    expect(result.credentials).toBeUndefined();
    expect(Object.keys(result.config)).toHaveLength(0);
  });

  it('skips empty-string env values', () => {
    const config = makeParsedConfig({ timeout: 30 });
    const env = { ADAPTER_CROWDSTRIKE_TIMEOUT: '' };

    const result = applyEnvOverrides(config, env);

    // Empty string is falsy, so it should be skipped
    expect(result.timeout).toBe(30);
  });

  it('does not mutate the original config', () => {
    const config = makeParsedConfig();
    const env = { ADAPTER_CROWDSTRIKE_REGION: 'eu-west-1' };

    const result = applyEnvOverrides(config, env);

    expect(result.config.region).toBe('eu-west-1');
    expect(config.config.region).toBeUndefined();
  });

  it('handles adapter names with hyphens', () => {
    const config = makeParsedConfig({ name: 'my-adapter' });
    const env = { ADAPTER_MY_ADAPTER_TIMEOUT: '60' };

    const result = applyEnvOverrides(config, env);

    expect(result.timeout).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// loadAdapterConfigs
// ---------------------------------------------------------------------------

describe('loadAdapterConfigs()', () => {
  it('loads multiple adapters from config section', () => {
    const section: AdaptersConfigSection = {
      adapters: {
        crowdstrike: makeRawBlock({ name: 'crowdstrike', type: 'edr' }),
        splunk: makeRawBlock({ name: 'splunk', type: 'siem', timeout: 60 }),
      },
    };

    const configs = loadAdapterConfigs(section, {});

    expect(configs.size).toBe(2);
    expect(configs.has('crowdstrike')).toBe(true);
    expect(configs.has('splunk')).toBe(true);

    const csConfig = configs.get('crowdstrike');
    expect(csConfig?.type).toBe('edr');

    const splunkConfig = configs.get('splunk');
    expect(splunkConfig?.type).toBe('siem');
    expect(splunkConfig?.timeout).toBe(60);
  });

  it('returns empty map for undefined section', () => {
    const configs = loadAdapterConfigs(undefined);
    expect(configs.size).toBe(0);
  });

  it('returns empty map when adapters key is undefined', () => {
    const configs = loadAdapterConfigs({});
    expect(configs.size).toBe(0);
  });

  it('applies env overrides to each adapter', () => {
    const section: AdaptersConfigSection = {
      adapters: {
        crowdstrike: makeRawBlock({ name: 'crowdstrike', type: 'edr' }),
      },
    };
    const env = { ADAPTER_CROWDSTRIKE_TIMEOUT: '90' };

    const configs = loadAdapterConfigs(section, env);
    const csConfig = configs.get('crowdstrike');

    expect(csConfig?.timeout).toBe(90);
  });

  it('loads a single adapter correctly', () => {
    const section: AdaptersConfigSection = {
      adapters: {
        mock: makeRawBlock({ name: 'mock', type: 'mock', enabled: false }),
      },
    };

    const configs = loadAdapterConfigs(section, {});

    expect(configs.size).toBe(1);
    const mockConfig = configs.get('mock');
    expect(mockConfig?.enabled).toBe(false);
    expect(mockConfig?.type).toBe('mock');
  });
});

// ---------------------------------------------------------------------------
// redactAdapterConfig
// ---------------------------------------------------------------------------

describe('redactAdapterConfig()', () => {
  it('redacts api_key in credentials', () => {
    const config = makeParsedConfig({
      credentials: {
        type: 'api_key',
        credentials: { api_key: 'super-secret-123' },
      },
    });

    const redacted = redactAdapterConfig(config);
    const creds = redacted.credentials as { type: string; credentials: Record<string, unknown> };

    expect(creds.type).toBe('api_key');
    expect(creds.credentials.api_key).toBe('***');
  });

  it('redacts secret, password, and token keys in config', () => {
    const config = makeParsedConfig({
      config: {
        secret: 'my-secret',
        password: 'my-password',
        token: 'my-token',
        region: 'us-east-1',
      },
    });

    const redacted = redactAdapterConfig(config);
    const cfg = redacted.config as Record<string, unknown>;

    expect(cfg.secret).toBe('***');
    expect(cfg.password).toBe('***');
    expect(cfg.token).toBe('***');
    expect(cfg.region).toBe('us-east-1');
  });

  it('preserves non-secret values', () => {
    const config = makeParsedConfig({
      config: {
        base_url: 'https://api.example.com',
        region: 'eu-west-1',
        max_connections: 10,
      },
    });

    const redacted = redactAdapterConfig(config);
    const cfg = redacted.config as Record<string, unknown>;

    expect(cfg.base_url).toBe('https://api.example.com');
    expect(cfg.region).toBe('eu-west-1');
    expect(cfg.max_connections).toBe(10);
  });

  it('does not mutate the original config object', () => {
    const config = makeParsedConfig({
      credentials: {
        type: 'api_key',
        credentials: { api_key: 'original-key' },
      },
      config: {
        secret: 'original-secret',
        region: 'us-east-1',
      },
    });

    redactAdapterConfig(config);

    // Original should be untouched
    expect(config.credentials?.credentials.api_key).toBe('original-key');
    expect(config.config.secret).toBe('original-secret');
  });

  it('preserves top-level fields', () => {
    const config = makeParsedConfig({
      name: 'crowdstrike',
      type: 'edr',
      enabled: true,
      timeout: 60,
      retry: { max_attempts: 5, backoff_ms: 2000, exponential: false },
    });

    const redacted = redactAdapterConfig(config);

    expect(redacted.name).toBe('crowdstrike');
    expect(redacted.type).toBe('edr');
    expect(redacted.enabled).toBe(true);
    expect(redacted.timeout).toBe(60);
    expect(redacted.retry).toEqual({
      max_attempts: 5,
      backoff_ms: 2000,
      exponential: false,
    });
  });

  it('handles config with no credentials', () => {
    const config = makeParsedConfig({ credentials: undefined });
    const redacted = redactAdapterConfig(config);

    expect(redacted.credentials).toBeUndefined();
  });

  it('redacts nested secret keys', () => {
    const config = makeParsedConfig({
      config: {
        nested: {
          api_key: 'nested-key',
          client_secret: 'nested-secret',
          hostname: 'example.com',
        },
      },
    });

    const redacted = redactAdapterConfig(config);
    const cfg = redacted.config as Record<string, unknown>;
    const nested = cfg.nested as Record<string, unknown>;

    expect(nested.api_key).toBe('***');
    expect(nested.client_secret).toBe('***');
    expect(nested.hostname).toBe('example.com');
  });

  it('redacts private_key and api_secret keys', () => {
    const config = makeParsedConfig({
      credentials: {
        type: 'certificate',
        credentials: {
          private_key: 'pem-data-here',
          api_secret: 'secret-value',
        },
      },
    });

    const redacted = redactAdapterConfig(config);
    const creds = redacted.credentials as { type: string; credentials: Record<string, unknown> };

    expect(creds.credentials.private_key).toBe('***');
    expect(creds.credentials.api_secret).toBe('***');
  });
});

// ---------------------------------------------------------------------------
// AdapterConfigError
// ---------------------------------------------------------------------------

describe('AdapterConfigError', () => {
  it('has correct name and properties', () => {
    const err = new AdapterConfigError('my-adapter', [
      'missing type',
      'invalid timeout',
    ]);

    expect(err.name).toBe('AdapterConfigError');
    expect(err.adapterName).toBe('my-adapter');
    expect(err.errors).toEqual(['missing type', 'invalid timeout']);
    expect(err.message).toContain('my-adapter');
    expect(err.message).toContain('missing type');
    expect(err.message).toContain('invalid timeout');
  });

  it('is instanceof Error', () => {
    const err = new AdapterConfigError('test', ['error']);

    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AdapterConfigError);
  });

  it('joins errors with semicolons in message', () => {
    const err = new AdapterConfigError('test', ['err1', 'err2', 'err3']);

    expect(err.message).toContain('err1; err2; err3');
  });
});

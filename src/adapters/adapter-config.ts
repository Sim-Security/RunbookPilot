/**
 * Adapter Configuration
 *
 * Per-adapter configuration loading from config.yml or environment variables.
 * Supports namespaced config (adapters.<name>.<key>), validation,
 * and secret redaction.
 *
 * @module adapters/adapter-config
 */

import type { AdapterConfig, AdapterCredentials, RetryConfig } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Configuration Schema
// ---------------------------------------------------------------------------

/**
 * Raw adapter config block as it appears in config.yml.
 */
export interface RawAdapterConfigBlock {
  name: string;
  type: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  credentials?: {
    type?: string;
    [key: string]: unknown;
  };
  timeout?: number;
  retry?: {
    max_attempts?: number;
    backoff_ms?: number;
    exponential?: boolean;
  };
}

/**
 * Top-level adapters section in config.yml.
 */
export interface AdaptersConfigSection {
  adapters?: Record<string, RawAdapterConfigBlock>;
}

// ---------------------------------------------------------------------------
// Config Defaults
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT = 30; // seconds
const DEFAULT_RETRY: RetryConfig = {
  max_attempts: 3,
  backoff_ms: 1000,
  exponential: true,
};

// ---------------------------------------------------------------------------
// Parse & Validate
// ---------------------------------------------------------------------------

/**
 * Parse a raw adapter config block into a validated AdapterConfig.
 */
export function parseAdapterConfig(
  name: string,
  raw: RawAdapterConfigBlock,
): AdapterConfig {
  const errors: string[] = [];

  if (!raw.type || typeof raw.type !== 'string') {
    errors.push(`Adapter '${name}': missing or invalid 'type'`);
  }

  const validTypes = ['edr', 'siem', 'firewall', 'iam', 'ticketing', 'notification', 'enrichment', 'mock', 'generic'];
  if (raw.type && !validTypes.includes(raw.type)) {
    errors.push(`Adapter '${name}': invalid type '${raw.type}'. Valid: ${validTypes.join(', ')}`);
  }

  if (raw.timeout !== undefined && (typeof raw.timeout !== 'number' || raw.timeout <= 0)) {
    errors.push(`Adapter '${name}': timeout must be a positive number`);
  }

  if (raw.retry) {
    if (raw.retry.max_attempts !== undefined && (typeof raw.retry.max_attempts !== 'number' || raw.retry.max_attempts < 1)) {
      errors.push(`Adapter '${name}': retry.max_attempts must be >= 1`);
    }
    if (raw.retry.backoff_ms !== undefined && (typeof raw.retry.backoff_ms !== 'number' || raw.retry.backoff_ms < 0)) {
      errors.push(`Adapter '${name}': retry.backoff_ms must be >= 0`);
    }
  }

  if (errors.length > 0) {
    throw new AdapterConfigError(name, errors);
  }

  let credentials: AdapterCredentials | undefined;
  if (raw.credentials) {
    const credType = raw.credentials.type as AdapterCredentials['type'] | undefined;
    if (credType) {
      const { type: _, ...rest } = raw.credentials;
      credentials = {
        type: credType,
        credentials: Object.fromEntries(
          Object.entries(rest).map(([k, v]) => [k, String(v)]),
        ),
      };
    }
  }

  return {
    name,
    type: raw.type,
    enabled: raw.enabled ?? true,
    config: raw.config ?? {},
    credentials,
    timeout: raw.timeout ?? DEFAULT_TIMEOUT,
    retry: raw.retry
      ? {
          max_attempts: raw.retry.max_attempts ?? DEFAULT_RETRY.max_attempts,
          backoff_ms: raw.retry.backoff_ms ?? DEFAULT_RETRY.backoff_ms,
          exponential: raw.retry.exponential ?? DEFAULT_RETRY.exponential,
        }
      : { ...DEFAULT_RETRY },
  };
}

// ---------------------------------------------------------------------------
// Environment Variable Overrides
// ---------------------------------------------------------------------------

/**
 * Env var prefix for adapter config: ADAPTER_<NAME>_<KEY>.
 * Example: ADAPTER_CROWDSTRIKE_API_KEY → adapters.crowdstrike.credentials.api_key
 */
const ENV_PREFIX = 'ADAPTER_';

/**
 * Apply environment variable overrides to an adapter config.
 * Pattern: ADAPTER_<UPPERNAME>_<KEY>
 *
 * Recognized keys:
 *   ADAPTER_<NAME>_ENABLED      → enabled (boolean)
 *   ADAPTER_<NAME>_TIMEOUT      → timeout (number)
 *   ADAPTER_<NAME>_API_KEY      → credentials.credentials.api_key
 *   ADAPTER_<NAME>_API_URL      → config.base_url
 *   ADAPTER_<NAME>_*            → config.<lowercase_key>
 */
export function applyEnvOverrides(
  config: AdapterConfig,
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>,
): AdapterConfig {
  const prefix = `${ENV_PREFIX}${config.name.toUpperCase().replace(/-/g, '_')}_`;
  const result = { ...config, config: { ...config.config } };

  for (const [key, value] of Object.entries(env)) {
    if (!key.startsWith(prefix) || !value) continue;

    const suffix = key.slice(prefix.length);

    switch (suffix) {
      case 'ENABLED':
        result.enabled = value.toLowerCase() === 'true';
        break;
      case 'TIMEOUT':
        result.timeout = parseInt(value, 10) || config.timeout;
        break;
      case 'API_KEY':
        result.credentials = {
          type: result.credentials?.type ?? 'api_key',
          credentials: {
            ...(result.credentials?.credentials ?? {}),
            api_key: value,
          },
        };
        break;
      case 'API_URL':
        result.config.base_url = value;
        break;
      default:
        result.config[suffix.toLowerCase()] = value;
        break;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Load All Adapter Configs
// ---------------------------------------------------------------------------

/**
 * Load all adapter configurations from a raw config section + env overrides.
 */
export function loadAdapterConfigs(
  section?: AdaptersConfigSection,
  env?: Record<string, string | undefined>,
): Map<string, AdapterConfig> {
  const configs = new Map<string, AdapterConfig>();

  if (section?.adapters) {
    for (const [name, raw] of Object.entries(section.adapters)) {
      const parsed = parseAdapterConfig(name, { ...raw, name });
      configs.set(name, applyEnvOverrides(parsed, env));
    }
  }

  return configs;
}

// ---------------------------------------------------------------------------
// Secret Redaction
// ---------------------------------------------------------------------------

/**
 * Keys in adapter config that should be redacted in logs.
 */
const SECRET_KEYS = new Set([
  'api_key',
  'api_secret',
  'password',
  'token',
  'secret',
  'client_secret',
  'private_key',
]);

/**
 * Redact secrets from an adapter config for safe logging.
 */
export function redactAdapterConfig(config: AdapterConfig): Record<string, unknown> {
  const redacted: Record<string, unknown> = {
    name: config.name,
    type: config.type,
    enabled: config.enabled,
    timeout: config.timeout,
    retry: config.retry,
    config: redactObject(config.config),
  };

  if (config.credentials) {
    redacted.credentials = {
      type: config.credentials.type,
      credentials: redactObject(
        config.credentials.credentials as Record<string, unknown>,
      ),
    };
  }

  return redacted;
}

function redactObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SECRET_KEYS.has(key.toLowerCase())) {
      result[key] = '***';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = redactObject(value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class AdapterConfigError extends Error {
  readonly adapterName: string;
  readonly errors: string[];

  constructor(adapterName: string, errors: string[]) {
    super(`Invalid configuration for adapter '${adapterName}': ${errors.join('; ')}`);
    this.name = 'AdapterConfigError';
    this.adapterName = adapterName;
    this.errors = errors;
  }
}

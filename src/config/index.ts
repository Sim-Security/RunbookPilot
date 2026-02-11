/**
 * RunbookPilot - Configuration System
 *
 * Loads configuration from environment variables and an optional config.yml file.
 * Validates all configuration at startup and never logs secrets.
 *
 * Priority: environment variables > config.yml > defaults
 */

import { existsSync, readFileSync } from 'node:fs';
import yaml from 'yaml';
import type { AutomationLevel } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AppConfig {
  logLevel: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  dbPath: string;
  playbookDirs: string[];
  adapterDirs: string[];
  automationLevel: AutomationLevel;
  openRouter: {
    baseUrl: string;
    apiKey: string;
    models: {
      fast: string;
      standard: string;
      quality: string;
    };
    timeout: number;
    maxTokens: number;
    temperature: number;
    retries: number;
  };
  server: {
    port: number;
    host: string;
  };
  approvalTimeout: number;
  maxExecutionTime: number;
}

// ---------------------------------------------------------------------------
// Valid value sets
// ---------------------------------------------------------------------------

const VALID_LOG_LEVELS = new Set<AppConfig['logLevel']>([
  'trace', 'debug', 'info', 'warn', 'error', 'fatal',
]);

const VALID_AUTOMATION_LEVELS = new Set<AutomationLevel>(['L0', 'L1', 'L2']);

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULTS: AppConfig = {
  logLevel: 'info',
  dbPath: './data/runbookpilot.db',
  playbookDirs: ['./playbooks'],
  adapterDirs: ['./adapters'],
  automationLevel: 'L0',
  openRouter: {
    baseUrl: 'https://openrouter.ai/api/v1',
    apiKey: '',
    models: {
      fast: 'openai/gpt-4o-mini',
      standard: 'anthropic/claude-3.5-sonnet',
      quality: 'anthropic/claude-3-opus',
    },
    timeout: 30_000,
    maxTokens: 4096,
    temperature: 0.1,
    retries: 3,
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  approvalTimeout: 3600,
  maxExecutionTime: 900,
};

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

let cachedConfig: AppConfig | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Read an environment variable, treating empty strings as undefined.
 * This ensures that `vi.stubEnv('VAR', '')` in tests correctly falls through to defaults.
 */
function envStr(key: string): string | undefined {
  const value = process.env[key];
  return value !== undefined && value !== '' ? value : undefined;
}

/**
 * Parse a comma-separated string into a trimmed, non-empty array of strings.
 */
function parseCommaSeparated(value: string): string[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Safely parse an integer from a string, returning undefined on failure.
 */
function safeParseInt(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}

/**
 * Safely parse a float from a string, returning undefined on failure.
 */
function safeParseFloat(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const parsed = Number.parseFloat(value);
  return Number.isNaN(parsed) ? undefined : parsed;
}

// ---------------------------------------------------------------------------
// YAML file loader
// ---------------------------------------------------------------------------

interface YamlConfig {
  log_level?: string;
  db_path?: string;
  playbook_dirs?: string[];
  adapter_dirs?: string[];
  automation_level?: string;
  openrouter?: {
    base_url?: string;
    api_key?: string;
    models?: {
      fast?: string;
      standard?: string;
      quality?: string;
    };
    timeout?: number;
    max_tokens?: number;
    temperature?: number;
    retries?: number;
  };
  server?: {
    port?: number;
    host?: string;
  };
  approval_timeout?: number;
  max_execution_time?: number;
}

function loadYamlConfig(configPath: string): YamlConfig {
  if (!existsSync(configPath)) {
    return {};
  }

  const raw = readFileSync(configPath, 'utf-8');
  const parsed: unknown = yaml.parse(raw);

  if (parsed === null || parsed === undefined || typeof parsed !== 'object') {
    return {};
  }

  return parsed as YamlConfig;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateConfig(config: AppConfig): void {
  const errors: string[] = [];

  if (!VALID_LOG_LEVELS.has(config.logLevel)) {
    errors.push(
      `Invalid log level "${config.logLevel}". Must be one of: ${[...VALID_LOG_LEVELS].join(', ')}`,
    );
  }

  if (!VALID_AUTOMATION_LEVELS.has(config.automationLevel)) {
    errors.push(
      `Invalid automation level "${config.automationLevel}". Must be one of: ${[...VALID_AUTOMATION_LEVELS].join(', ')}`,
    );
  }

  if (config.server.port < 1 || config.server.port > 65535) {
    errors.push(`Invalid server port ${config.server.port}. Must be between 1 and 65535.`);
  }

  if (config.openRouter.timeout < 0) {
    errors.push(`Invalid OpenRouter timeout ${config.openRouter.timeout}. Must be non-negative.`);
  }

  if (config.openRouter.maxTokens < 1) {
    errors.push(`Invalid OpenRouter maxTokens ${config.openRouter.maxTokens}. Must be positive.`);
  }

  if (config.openRouter.temperature < 0 || config.openRouter.temperature > 2) {
    errors.push(
      `Invalid OpenRouter temperature ${config.openRouter.temperature}. Must be between 0 and 2.`,
    );
  }

  if (config.openRouter.retries < 0) {
    errors.push(`Invalid OpenRouter retries ${config.openRouter.retries}. Must be non-negative.`);
  }

  if (config.approvalTimeout < 0) {
    errors.push(`Invalid approval timeout ${config.approvalTimeout}. Must be non-negative.`);
  }

  if (config.maxExecutionTime < 0) {
    errors.push(`Invalid max execution time ${config.maxExecutionTime}. Must be non-negative.`);
  }

  if (config.playbookDirs.length === 0) {
    errors.push('At least one playbook directory must be specified.');
  }

  if (config.adapterDirs.length === 0) {
    errors.push('At least one adapter directory must be specified.');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n  - ${errors.join('\n  - ')}`);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load and validate configuration.
 *
 * Priority (highest to lowest):
 *   1. Environment variables
 *   2. YAML config file (if provided or found)
 *   3. Built-in defaults
 *
 * @param configPath - Optional path to a config.yml file
 * @returns Validated AppConfig
 * @throws Error if validation fails
 */
export function loadConfig(configPath?: string): AppConfig {
  // Load YAML if a path is specified and the file exists
  const yamlCfg: YamlConfig = configPath ? loadYamlConfig(configPath) : {};

  const config: AppConfig = {
    // -- Log level --------------------------------------------------------
    logLevel: (envStr('LOG_LEVEL') ?? yamlCfg.log_level ?? DEFAULTS.logLevel) as AppConfig['logLevel'],

    // -- Database ---------------------------------------------------------
    dbPath: envStr('RUNBOOKPILOT_DB_PATH') ?? yamlCfg.db_path ?? DEFAULTS.dbPath,

    // -- Directories ------------------------------------------------------
    playbookDirs: envStr('PLAYBOOK_DIRS')
      ? parseCommaSeparated(envStr('PLAYBOOK_DIRS')!)
      : yamlCfg.playbook_dirs ?? DEFAULTS.playbookDirs,

    adapterDirs: envStr('ADAPTER_DIRS')
      ? parseCommaSeparated(envStr('ADAPTER_DIRS')!)
      : yamlCfg.adapter_dirs ?? DEFAULTS.adapterDirs,

    // -- Automation level -------------------------------------------------
    automationLevel: (envStr('AUTOMATION_LEVEL') ??
      yamlCfg.automation_level ??
      DEFAULTS.automationLevel) as AutomationLevel,

    // -- OpenRouter -------------------------------------------------------
    openRouter: {
      baseUrl:
        envStr('OPENROUTER_BASE_URL') ??
        yamlCfg.openrouter?.base_url ??
        DEFAULTS.openRouter.baseUrl,

      apiKey:
        envStr('OPENROUTER_API_KEY') ??
        yamlCfg.openrouter?.api_key ??
        DEFAULTS.openRouter.apiKey,

      models: {
        fast:
          envStr('OPENROUTER_MODEL_FAST') ??
          yamlCfg.openrouter?.models?.fast ??
          DEFAULTS.openRouter.models.fast,

        standard:
          envStr('OPENROUTER_MODEL_STANDARD') ??
          yamlCfg.openrouter?.models?.standard ??
          DEFAULTS.openRouter.models.standard,

        quality:
          envStr('OPENROUTER_MODEL_QUALITY') ??
          yamlCfg.openrouter?.models?.quality ??
          DEFAULTS.openRouter.models.quality,
      },

      timeout:
        safeParseInt(envStr('OPENROUTER_TIMEOUT')) ??
        yamlCfg.openrouter?.timeout ??
        DEFAULTS.openRouter.timeout,

      maxTokens:
        safeParseInt(envStr('OPENROUTER_MAX_TOKENS')) ??
        yamlCfg.openrouter?.max_tokens ??
        DEFAULTS.openRouter.maxTokens,

      temperature:
        safeParseFloat(envStr('OPENROUTER_TEMPERATURE')) ??
        yamlCfg.openrouter?.temperature ??
        DEFAULTS.openRouter.temperature,

      retries:
        safeParseInt(envStr('OPENROUTER_RETRIES')) ??
        yamlCfg.openrouter?.retries ??
        DEFAULTS.openRouter.retries,
    },

    // -- Server -----------------------------------------------------------
    server: {
      port:
        safeParseInt(envStr('SERVER_PORT')) ??
        yamlCfg.server?.port ??
        DEFAULTS.server.port,

      host:
        envStr('SERVER_HOST') ??
        yamlCfg.server?.host ??
        DEFAULTS.server.host,
    },

    // -- Timeouts ---------------------------------------------------------
    approvalTimeout:
      safeParseInt(envStr('APPROVAL_TIMEOUT')) ??
      yamlCfg.approval_timeout ??
      DEFAULTS.approvalTimeout,

    maxExecutionTime:
      safeParseInt(envStr('MAX_EXECUTION_TIME')) ??
      yamlCfg.max_execution_time ??
      DEFAULTS.maxExecutionTime,
  };

  validateConfig(config);

  cachedConfig = config;
  return config;
}

/**
 * Return the previously loaded configuration.
 *
 * @throws Error if loadConfig() has not been called yet.
 */
export function getConfig(): AppConfig {
  if (cachedConfig === null) {
    throw new Error(
      'Configuration has not been loaded. Call loadConfig() before getConfig().',
    );
  }
  return cachedConfig;
}

/**
 * Return a deep copy of the config with all secret values replaced by '***'.
 * This is safe to log, display, or include in error reports.
 */
export function redactSecrets(config: AppConfig): Record<string, unknown> {
  return {
    logLevel: config.logLevel,
    dbPath: config.dbPath,
    playbookDirs: [...config.playbookDirs],
    adapterDirs: [...config.adapterDirs],
    automationLevel: config.automationLevel,
    openRouter: {
      baseUrl: config.openRouter.baseUrl,
      apiKey: config.openRouter.apiKey ? '***' : '',
      models: { ...config.openRouter.models },
      timeout: config.openRouter.timeout,
      maxTokens: config.openRouter.maxTokens,
      temperature: config.openRouter.temperature,
      retries: config.openRouter.retries,
    },
    server: { ...config.server },
    approvalTimeout: config.approvalTimeout,
    maxExecutionTime: config.maxExecutionTime,
  };
}

/**
 * Reset the cached config. Primarily for testing purposes.
 */
export function resetConfig(): void {
  cachedConfig = null;
}

/**
 * Adapter Registry
 *
 * Discovers, loads, and manages adapters by name and action type.
 * Supports lazy initialization, health checking, and lifecycle management.
 *
 * @module adapters/registry
 */

import type { StepAction, AdapterConfig } from '../types/playbook.ts';
import type { ActionAdapter, HealthCheckResult } from './adapter-interface.ts';
import type { StepAdapter, AdapterResolver } from '../engine/step-executor.ts';

// ---------------------------------------------------------------------------
// Registry Types
// ---------------------------------------------------------------------------

export interface RegisteredAdapter {
  adapter: ActionAdapter;
  config: AdapterConfig;
  registeredAt: string; // ISO 8601
  lastHealthCheck?: HealthCheckResult;
}

export interface RegistryStats {
  totalAdapters: number;
  enabledAdapters: number;
  disabledAdapters: number;
  actionCoverage: Map<StepAction, string[]>;
}

// ---------------------------------------------------------------------------
// Adapter Registry
// ---------------------------------------------------------------------------

export class AdapterRegistry {
  private readonly adapters = new Map<string, RegisteredAdapter>();
  /** Action → adapter name(s) lookup for fast resolution. */
  private readonly actionIndex = new Map<StepAction, Set<string>>();

  /**
   * Register an adapter with the registry.
   * Initializes the adapter with the provided config.
   *
   * @throws if adapter name already registered
   */
  async register(adapter: ActionAdapter, config: AdapterConfig): Promise<void> {
    if (this.adapters.has(adapter.name)) {
      throw new Error(`Adapter '${adapter.name}' is already registered`);
    }

    await adapter.initialize(config);

    const entry: RegisteredAdapter = {
      adapter,
      config,
      registeredAt: new Date().toISOString(),
    };

    this.adapters.set(adapter.name, entry);

    // Index actions
    for (const action of adapter.supportedActions) {
      let names = this.actionIndex.get(action);
      if (!names) {
        names = new Set();
        this.actionIndex.set(action, names);
      }
      names.add(adapter.name);
    }
  }

  /**
   * Unregister an adapter. Calls shutdown() if implemented.
   */
  async unregister(name: string): Promise<boolean> {
    const entry = this.adapters.get(name);
    if (!entry) return false;

    // Remove from action index
    for (const action of entry.adapter.supportedActions) {
      const names = this.actionIndex.get(action);
      if (names) {
        names.delete(name);
        if (names.size === 0) {
          this.actionIndex.delete(action);
        }
      }
    }

    // Shutdown
    if (entry.adapter.shutdown) {
      await entry.adapter.shutdown();
    }

    this.adapters.delete(name);
    return true;
  }

  /**
   * Get an adapter by name.
   */
  get(name: string): ActionAdapter | undefined {
    return this.adapters.get(name)?.adapter;
  }

  /**
   * Get all adapters that support a given action.
   */
  getForAction(action: StepAction): ActionAdapter[] {
    const names = this.actionIndex.get(action);
    if (!names) return [];

    return Array.from(names)
      .map((n) => this.adapters.get(n)?.adapter)
      .filter((a): a is ActionAdapter => a !== undefined);
  }

  /**
   * Check if an adapter is registered.
   */
  has(name: string): boolean {
    return this.adapters.has(name);
  }

  /**
   * List all registered adapter names.
   */
  list(): string[] {
    return Array.from(this.adapters.keys());
  }

  /**
   * List all registered adapters with their details.
   */
  listDetailed(): RegisteredAdapter[] {
    return Array.from(this.adapters.values());
  }

  /**
   * Get number of registered adapters.
   */
  get size(): number {
    return this.adapters.size;
  }

  /**
   * Run health checks on all registered adapters.
   */
  async healthCheckAll(): Promise<Map<string, HealthCheckResult>> {
    const results = new Map<string, HealthCheckResult>();

    const checks = Array.from(this.adapters.entries()).map(
      async ([name, entry]) => {
        try {
          const result = await entry.adapter.healthCheck();
          entry.lastHealthCheck = result;
          results.set(name, result);
        } catch (err) {
          const result: HealthCheckResult = {
            status: 'unhealthy',
            message: err instanceof Error ? err.message : String(err),
            checkedAt: new Date().toISOString(),
          };
          entry.lastHealthCheck = result;
          results.set(name, result);
        }
      },
    );

    await Promise.all(checks);
    return results;
  }

  /**
   * Run health check on a single adapter.
   */
  async healthCheck(name: string): Promise<HealthCheckResult> {
    const entry = this.adapters.get(name);
    if (!entry) {
      return {
        status: 'unknown',
        message: `Adapter '${name}' not registered`,
        checkedAt: new Date().toISOString(),
      };
    }

    try {
      const result = await entry.adapter.healthCheck();
      entry.lastHealthCheck = result;
      return result;
    } catch (err) {
      const result: HealthCheckResult = {
        status: 'unhealthy',
        message: err instanceof Error ? err.message : String(err),
        checkedAt: new Date().toISOString(),
      };
      entry.lastHealthCheck = result;
      return result;
    }
  }

  /**
   * Get registry statistics.
   */
  getStats(): RegistryStats {
    const actionCoverage = new Map<StepAction, string[]>();
    let enabled = 0;
    let disabled = 0;

    for (const [_name, entry] of this.adapters) {
      if (entry.config.enabled) {
        enabled++;
      } else {
        disabled++;
      }
    }

    for (const [action, names] of this.actionIndex) {
      actionCoverage.set(action, Array.from(names));
    }

    return {
      totalAdapters: this.adapters.size,
      enabledAdapters: enabled,
      disabledAdapters: disabled,
      actionCoverage,
    };
  }

  /**
   * Create an AdapterResolver compatible with the S1 step-executor.
   * Bridges the full ActionAdapter interface to the minimal StepAdapter.
   */
  createResolver(): AdapterResolver {
    return (executorName: string): StepAdapter | undefined => {
      const adapter = this.get(executorName);
      if (!adapter) return undefined;

      // ActionAdapter is a superset of StepAdapter — just return it
      return adapter;
    };
  }

  /**
   * Shutdown all adapters and clear the registry.
   */
  async shutdownAll(): Promise<void> {
    const shutdowns = Array.from(this.adapters.entries()).map(
      async ([_name, entry]) => {
        if (entry.adapter.shutdown) {
          try {
            await entry.adapter.shutdown();
          } catch {
            // Best-effort shutdown
          }
        }
      },
    );

    await Promise.all(shutdowns);
    this.adapters.clear();
    this.actionIndex.clear();
  }
}

// ---------------------------------------------------------------------------
// Singleton Factory
// ---------------------------------------------------------------------------

let defaultRegistry: AdapterRegistry | undefined;

/**
 * Get or create the default adapter registry.
 */
export function getAdapterRegistry(): AdapterRegistry {
  if (!defaultRegistry) {
    defaultRegistry = new AdapterRegistry();
  }
  return defaultRegistry;
}

/**
 * Reset the default registry (for testing).
 */
export function resetAdapterRegistry(): void {
  defaultRegistry = undefined;
}

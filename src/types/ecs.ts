/**
 * ECS (Elastic Common Schema) TypeScript Types for RunbookPilot
 *
 * These types define the structure of ECS-normalized alert events ingested
 * by RunbookPilot. All alerts -- regardless of source (SIEM, EDR, DetectForge,
 * manual) -- are normalized to this schema before processing.
 *
 * Reference: https://www.elastic.co/guide/en/ecs/current/index.html
 *
 * @module types/ecs
 */

// ─── ECS Event Fields ────────────────────────────────────────────────────────

/**
 * ECS event categorization fields.
 *
 * - `kind`: High-level classification (alert, event, metric)
 * - `category`: Event category array (e.g., ["process", "malware"])
 * - `type`: Event type array (e.g., ["start", "creation"])
 * - `severity`: Numeric severity 0-100 (0 = informational, 100 = critical)
 */
export interface EventFields {
  kind: 'alert' | 'event' | 'metric';
  category: string[];
  type: string[];
  action?: string;
  outcome?: 'success' | 'failure' | 'unknown';
  severity: number; // 0-100
  risk_score?: number; // 0-100
  dataset?: string;
  module?: string;
}

// ─── ECS Host Fields ─────────────────────────────────────────────────────────

/**
 * ECS host identification and metadata fields.
 *
 * Describes the host (endpoint, server, workstation) associated with the event.
 */
export interface HostFields {
  hostname?: string;
  name?: string;
  id?: string;
  ip?: string[];
  mac?: string[];
  os?: {
    family?: string;
    name?: string;
    platform?: string;
    version?: string;
  };
}

// ─── ECS Network Fields ──────────────────────────────────────────────────────

/**
 * ECS network endpoint fields (used for source and destination).
 *
 * Represents a network endpoint with optional geolocation data.
 */
export interface NetworkFields {
  ip?: string;
  port?: number;
  domain?: string;
  geo?: {
    country_iso_code?: string;
    city_name?: string;
  };
}

// ─── ECS Process Fields ──────────────────────────────────────────────────────

/**
 * ECS process fields describing an observed process.
 *
 * Includes parent process information and file hashes for correlation.
 */
export interface ProcessFields {
  pid?: number;
  name?: string;
  executable?: string;
  command_line?: string;
  parent?: {
    pid?: number;
    name?: string;
  };
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

// ─── ECS File Fields ─────────────────────────────────────────────────────────

/**
 * ECS file fields describing a file involved in the event.
 *
 * Includes file hashes for IOC matching and threat intel lookups.
 */
export interface FileFields {
  path?: string;
  name?: string;
  extension?: string;
  size?: number;
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

// ─── ECS User Fields ─────────────────────────────────────────────────────────

/**
 * ECS user fields identifying the user associated with the event.
 */
export interface UserFields {
  id?: string;
  name?: string;
  email?: string;
  domain?: string;
  roles?: string[];
}

// ─── ECS Threat Fields ───────────────────────────────────────────────────────

/**
 * ECS threat fields for MITRE ATT&CK mapping.
 *
 * - `framework`: Always 'MITRE ATT&CK' for RunbookPilot
 * - `technique`: ATT&CK technique IDs and names (e.g., T1059.001)
 * - `tactic`: ATT&CK tactic IDs and names (e.g., TA0002)
 * - `indicator`: Threat indicator for IOC-based alerts
 */
export interface ThreatFields {
  framework: 'MITRE ATT&CK';
  technique?: {
    id: string[];
    name: string[];
  };
  tactic?: {
    id: string[];
    name: string[];
  };
  indicator?: {
    type?: string;
    value?: string;
  };
}

// ─── DetectForge Metadata ────────────────────────────────────────────────────

/**
 * DetectForge metadata (handoff from DetectForge detection pipeline).
 *
 * When alerts originate from DetectForge-generated detection rules, this
 * metadata is attached under the `x-detectforge` key. It enables:
 * - Tracing alerts back to the originating rule and threat intel
 * - Automatic runbook selection via `suggested_runbook`
 * - Confidence-based automation level decisions
 */
export interface DetectForgeMetadata {
  rule_id: string;
  rule_name: string;
  rule_version: string;
  generated_at: string; // ISO8601
  intel_source?: string;
  intel_url?: string;
  confidence: 'low' | 'medium' | 'high';
  suggested_runbook?: string; // Runbook ID
}

// ─── Alert Event (Top-Level ECS Document) ────────────────────────────────────

/**
 * Incoming alert event normalized to ECS format.
 *
 * This is the primary input type for RunbookPilot's execution engine.
 * All alert sources (SIEM webhooks, STDIN JSON, file ingestion, DetectForge
 * handoff) are normalized to this structure before playbook matching and
 * execution.
 *
 * Required fields:
 * - `@timestamp`: ISO8601 timestamp of the alert
 * - `event`: Event categorization (kind, category, type, severity)
 *
 * Optional ECS field groups are included based on alert context:
 * - `host`: Endpoint involved in the alert
 * - `source`/`destination`: Network endpoints (for network-based alerts)
 * - `process`: Process details (for endpoint-based alerts)
 * - `file`: File details (for file-based alerts)
 * - `user`: User context
 * - `threat`: MITRE ATT&CK mapping
 * - `x-detectforge`: DetectForge pipeline metadata
 */
export interface AlertEvent {
  '@timestamp': string; // ISO8601
  event: EventFields;
  host?: HostFields;
  source?: NetworkFields;
  destination?: NetworkFields;
  process?: ProcessFields;
  file?: FileFields;
  user?: UserFields;
  threat?: ThreatFields;
  tags?: string[];
  'x-detectforge'?: DetectForgeMetadata;
}

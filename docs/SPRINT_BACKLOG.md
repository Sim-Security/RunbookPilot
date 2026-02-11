# RunbookPilot Sprint Backlog

**Project:** RunbookPilot - AI-Assisted SOC Runbook Automation with Human-in-the-Loop Graduated Autonomy
**Stack:** Bun + TypeScript + Vitest
**Created:** 2026-02-10
**Status:** S0 Ready to Start

---

## Table of Contents
- [Sprint Overview](#sprint-overview)
- [S0: Foundation](#s0-foundation)
- [S1: Execution Engine (L0-L1)](#s1-execution-engine-l0-l1)
- [S2: Adapter Layer](#s2-adapter-layer)
- [S3: L2 Simulation Mode](#s3-l2-simulation-mode)
- [S4: Reference Runbooks & Integration](#s4-reference-runbooks--integration)
- [S5: Dashboard & Polish](#s5-dashboard--polish)
- [Sprint Summary](#sprint-summary)

---

## Sprint Overview

RunbookPilot is designed as a graduated autonomy system for SOC playbook automation:

- **L0 (Display Only):** Show checklist, no automation
- **L1 (Semi-Automated):** Execute read-only actions, require approval for write actions
- **L2 (Simulated):** Simulate write actions, build approval queue for one-click execution

This backlog follows the DetectForge sprint pattern with detailed, actionable tickets. Each sprint builds on the previous, enabling incremental delivery and testing.

**Total Sprints:** 6 (S0-S5)
**Total Tickets:** 73
**Estimated Timeline:** 6-8 weeks (assuming parallel work similar to DetectForge)

---

## S0: Foundation

**Goal:** Establish core infrastructure, project structure, schema definitions, and test harness.
**Tickets:** 12
**Priority:** All P0-P1 (foundation work)

### S0-001: Project Scaffolding and Bun Setup
**Type:** Infrastructure
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Initialize the RunbookPilot project with Bun runtime, TypeScript configuration, and folder structure matching DetectForge patterns.
**Acceptance Criteria:**
- [ ] `bun init` completed with TypeScript support
- [ ] Folder structure created: `src/`, `tests/`, `docs/`, `scripts/`, `adapters/`, `playbooks/`
- [ ] `package.json` configured with project metadata
- [ ] `.gitignore` configured (node_modules, .env, dist/, coverage/)
- [ ] `tsconfig.json` with strict mode enabled
- [ ] `bun.lockb` committed
**Dependencies:** None
**Tests Required:** N/A (infrastructure)

---

### S0-002: Vitest Test Framework Setup
**Type:** Infrastructure
**Priority:** P0 (blocker)
**Estimate:** S (< 2hr)
**Description:** Configure Vitest for unit and integration testing with coverage reporting.
**Acceptance Criteria:**
- [ ] `vitest` and `@vitest/coverage-v8` installed
- [ ] `vitest.config.ts` created with coverage thresholds (80%+)
- [ ] Test scripts in `package.json` (`bun run test`, `bun run test:watch`, `bun run test:coverage`)
- [ ] Sample test file runs successfully
- [ ] Coverage reports to `coverage/` directory
**Dependencies:** S0-001
**Tests Required:** Sample test to verify framework works

---

### S0-003: CLI Framework with Commander.js
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement CLI entrypoint with Commander.js for playbook execution and management.
**Acceptance Criteria:**
- [ ] `commander` installed
- [ ] `src/cli.ts` created as main entrypoint
- [ ] Commands defined: `run`, `validate`, `list`, `version`
- [ ] Global flags: `--verbose`, `--dry-run`, `--automation-level`, `--enable-l2`
- [ ] Help text displays correctly
- [ ] CLI executable via `bun run cli` or shebang
**Dependencies:** S0-001
**Tests Required:** CLI argument parsing unit tests

---

### S0-004: YAML Playbook Schema Definition
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** L (4-8hr)
**Description:** Define the canonical YAML schema for RunbookPilot playbooks, covering metadata, triggers, steps, and actions.
**Acceptance Criteria:**
- [ ] Schema documented in `docs/PLAYBOOK_SCHEMA.md`
- [ ] Schema covers: `metadata`, `triggers`, `steps`, `actions`, `rollback`, `approval_policy`
- [ ] Parameter templating syntax defined (e.g., `{{ alert.host_id }}`)
- [ ] Error handling modes defined: `halt`, `continue`, `skip`
- [ ] Automation level per step: `L0`, `L1`, `L2`
- [ ] Example playbook created in `playbooks/examples/basic.yml`
**Dependencies:** None
**Tests Required:** Schema validation tests in S0-005

---

### S0-005: TypeScript Types for Playbook Schema
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Create TypeScript interfaces/types representing the playbook schema for type safety.
**Acceptance Criteria:**
- [ ] `src/types/playbook.ts` created
- [ ] Types: `Playbook`, `Metadata`, `Trigger`, `Step`, `Action`, `RollbackConfig`, `ApprovalPolicy`
- [ ] Enums: `AutomationLevel`, `ErrorHandlingMode`, `StepStatus`
- [ ] Types exported from `src/types/index.ts`
- [ ] No type errors in compilation
**Dependencies:** S0-004
**Tests Required:** Type compilation tests

---

### S0-006: YAML Schema Validator
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** L (4-8hr)
**Description:** Implement schema validator using Zod or similar to validate playbook YAML files.
**Acceptance Criteria:**
- [ ] `zod` installed
- [ ] `src/validators/playbook-validator.ts` created
- [ ] Zod schema matches TypeScript types
- [ ] Validation function returns detailed error messages
- [ ] Validates required fields, data types, and enum values
- [ ] CLI command `runbookpilot validate <playbook.yml>` works
**Dependencies:** S0-004, S0-005
**Tests Required:** Unit tests with valid/invalid playbooks

---

### S0-007: ECS Event Format Types
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Define TypeScript types for Elastic Common Schema (ECS) events used as playbook inputs.
**Acceptance Criteria:**
- [ ] `src/types/ecs.ts` created
- [ ] Core ECS fields typed: `@timestamp`, `event.*`, `host.*`, `process.*`, `network.*`, `file.*`
- [ ] Alert-specific fields: `signal.*`, `kibana.alert.*`
- [ ] DetectForge metadata fields: `x-detectforge.*`
- [ ] Sample ECS event JSON created in `tests/fixtures/ecs-event.json`
**Dependencies:** S0-005
**Tests Required:** Type validation tests

---

### S0-008: Configuration System
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement configuration loading from environment variables and config files.
**Acceptance Criteria:**
- [ ] `.env.example` created with all config options documented
- [ ] `src/config/index.ts` loads config from env and optional `config.yml`
- [ ] Config includes: log level, database path, adapter paths, LLM settings, automation defaults
- [ ] Config validated at startup with clear error messages
- [ ] Secrets never logged or displayed
**Dependencies:** S0-001
**Tests Required:** Config loading unit tests with mock env vars

---

### S0-009: Structured Logging Infrastructure
**Type:** Infrastructure
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement structured JSON logging with log levels and correlation IDs.
**Acceptance Criteria:**
- [ ] `pino` or similar structured logger installed
- [ ] `src/logging/logger.ts` created
- [ ] Log levels: `trace`, `debug`, `info`, `warn`, `error`, `fatal`
- [ ] Correlation ID injected per execution
- [ ] Logs written to stdout (JSON) and optional file
- [ ] Sensitive data redacted from logs
**Dependencies:** S0-008
**Tests Required:** Log output format tests

---

### S0-010: SQLite Database Setup
**Type:** Infrastructure
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Initialize SQLite database for execution history, audit logs, and approval queue.
**Acceptance Criteria:**
- [ ] `better-sqlite3` installed
- [ ] `src/db/schema.sql` created with tables: `executions`, `audit_logs`, `approval_queue`
- [ ] `src/db/index.ts` initializes database and runs migrations
- [ ] Database connection pooling configured
- [ ] Migration system in place (version tracking)
- [ ] Database path configurable via config
**Dependencies:** S0-008
**Tests Required:** Database initialization tests with in-memory DB

---

### S0-011: CI/CD Pipeline Setup
**Type:** Infrastructure
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Configure GitHub Actions for automated testing, linting, and coverage reporting.
**Acceptance Criteria:**
- [ ] `.github/workflows/ci.yml` created
- [ ] Workflow runs on push and PR
- [ ] Steps: checkout, install Bun, install deps, lint, test, coverage
- [ ] Coverage uploaded to Codecov or similar
- [ ] Workflow status badge added to README
- [ ] Matrix testing (optional: multiple Node/Bun versions)
**Dependencies:** S0-002
**Tests Required:** N/A (CI infrastructure)

---

### S0-012: Docker Setup
**Type:** Infrastructure
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Create Dockerfile and docker-compose.yml for containerized deployment.
**Acceptance Criteria:**
- [ ] `Dockerfile` created with Bun base image
- [ ] Multi-stage build for smaller production image
- [ ] `docker-compose.yml` with RunbookPilot service
- [ ] Volume mounts for playbooks and database
- [ ] Environment variable passing configured
- [ ] `docker build` and `docker-compose up` work
**Dependencies:** S0-001, S0-008
**Tests Required:** Docker build test in CI

---

## S1: Execution Engine (L0-L1)

**Goal:** Build the core deterministic state machine that executes playbooks at L0 (display only) and L1 (read-only auto, write approval).
**Tickets:** 14
**Priority:** P0-P1 (core engine)

### S1-001: State Machine Implementation
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** L (4-8hr)
**Description:** Implement the playbook execution state machine with state transitions and event handling.
**Acceptance Criteria:**
- [ ] `src/engine/state-machine.ts` created
- [ ] States defined: `idle`, `planning`, `awaiting_approval`, `executing`, `completed`, `failed`, `rolled_back`
- [ ] State transition logic implemented with guards
- [ ] State persistence to SQLite
- [ ] Event emitter for state change notifications
- [ ] State machine diagram documented
**Dependencies:** S0-010
**Tests Required:** State transition unit tests for all valid/invalid transitions

---

### S1-002: Execution Context Manager
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement execution context to store and pass data between playbook steps.
**Acceptance Criteria:**
- [ ] `src/engine/context.ts` created
- [ ] Context stores: input event, step outputs, intermediate results, metadata
- [ ] Context supports nested data access (e.g., `alert.host.ip`)
- [ ] Context immutability per step (copy-on-write)
- [ ] Context serialization to JSON for persistence
- [ ] Context restored from database on resume
**Dependencies:** S0-007, S0-010
**Tests Required:** Context data storage and retrieval tests

---

### S1-003: Parameter Templating Engine
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement templating engine to resolve `{{ variable }}` placeholders in playbook actions.
**Acceptance Criteria:**
- [ ] `src/engine/templating.ts` created
- [ ] Supports variable interpolation: `{{ alert.host_id }}`
- [ ] Supports filters/transforms: `{{ timestamp | format_date }}`
- [ ] Supports conditionals: `{{ if alert.severity == 'critical' }}`
- [ ] Handles missing variables gracefully (error or default)
- [ ] Template syntax documented
**Dependencies:** S1-002
**Tests Required:** Template resolution unit tests with edge cases

---

### S1-004: L0 Executor (Display Only)
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement L0 automation level executor that displays checklist without executing actions.
**Acceptance Criteria:**
- [ ] `src/engine/executors/l0-executor.ts` created
- [ ] Displays playbook steps as checklist
- [ ] Shows templated action details (what would be executed)
- [ ] Prompts analyst for manual confirmation per step
- [ ] Records manual completion in audit log
- [ ] CLI output formatted for readability
**Dependencies:** S1-001, S1-003
**Tests Required:** L0 executor unit tests with mock playbooks

---

### S1-005: Action Classification (Read vs Write)
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** S (< 2hr)
**Description:** Implement action classification to distinguish read-only from write actions for L1 automation.
**Acceptance Criteria:**
- [ ] `src/engine/action-classifier.ts` created
- [ ] Read-only actions: `query`, `enrich`, `display`, `log`
- [ ] Write actions: `isolate`, `block`, `quarantine`, `delete`, `modify`
- [ ] Classification configurable per adapter
- [ ] Unknown actions default to write (safe default)
**Dependencies:** None
**Tests Required:** Classification unit tests for all action types

---

### S1-006: L1 Executor (Semi-Automated)
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** L (4-8hr)
**Description:** Implement L1 executor that auto-executes read-only actions and prompts for write actions.
**Acceptance Criteria:**
- [ ] `src/engine/executors/l1-executor.ts` created
- [ ] Auto-executes read-only actions without approval
- [ ] Prompts for approval before write actions
- [ ] Displays action context and impact before approval
- [ ] Supports timeout for approval (auto-skip after N seconds)
- [ ] Records approvals/rejections in audit log
**Dependencies:** S1-001, S1-003, S1-005
**Tests Required:** L1 executor unit tests with mock adapters and approvals

---

### S1-007: Approval Gate Manager
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement approval gate with timeout, multi-approver support, and audit trail.
**Acceptance Criteria:**
- [ ] `src/engine/approval-gate.ts` created
- [ ] Prompts analyst with action details and risk assessment
- [ ] Configurable timeout (default 5 minutes)
- [ ] Timeout behavior: `skip`, `halt`, `auto-approve` (configurable)
- [ ] Approval stored in audit log with timestamp and approver
- [ ] Supports CLI and future UI approvals
**Dependencies:** S1-006
**Tests Required:** Approval flow tests including timeout scenarios

---

### S1-008: Step Executor with Error Handling
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement individual step executor with error handling modes (halt/continue/skip).
**Acceptance Criteria:**
- [ ] `src/engine/step-executor.ts` created
- [ ] Executes step action via adapter
- [ ] Applies parameter templating before execution
- [ ] Handles errors per step config: `halt`, `continue`, `skip`
- [ ] Stores step result in execution context
- [ ] Emits step completion events
- [ ] Timeout per step (configurable)
**Dependencies:** S1-003, S1-005
**Tests Required:** Step execution tests with all error handling modes

---

### S1-009: Rollback Engine
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement rollback execution for playbooks with rollback steps defined.
**Acceptance Criteria:**
- [ ] `src/engine/rollback.ts` created
- [ ] Executes rollback steps in reverse order on failure
- [ ] Rollback triggered by error handling mode or manual command
- [ ] Rollback steps have own error handling (best-effort)
- [ ] Rollback status tracked in state machine
- [ ] Rollback actions logged separately in audit log
**Dependencies:** S1-001, S1-008
**Tests Required:** Rollback execution tests with failure scenarios

---

### S1-010: Playbook Loader and Parser
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement YAML playbook loader with validation and parsing.
**Acceptance Criteria:**
- [ ] `src/engine/playbook-loader.ts` created
- [ ] Loads YAML from file path
- [ ] Validates against schema (S0-006)
- [ ] Parses into typed Playbook object
- [ ] Handles file read errors gracefully
- [ ] Caches parsed playbooks (optional)
**Dependencies:** S0-006
**Tests Required:** Loader tests with valid/invalid YAML files

---

### S1-011: Execution Orchestrator
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** XL (8+hr)
**Description:** Implement main orchestrator that coordinates playbook execution across all components.
**Acceptance Criteria:**
- [ ] `src/engine/orchestrator.ts` created
- [ ] Loads playbook and validates
- [ ] Initializes execution context with input event
- [ ] Selects executor based on automation level (L0/L1/L2)
- [ ] Coordinates state machine transitions
- [ ] Handles execution lifecycle (start, pause, resume, cancel)
- [ ] Persists execution state to database
- [ ] Returns execution result
**Dependencies:** S1-001, S1-002, S1-004, S1-006, S1-010
**Tests Required:** End-to-end orchestrator tests with sample playbooks

---

### S1-012: Audit Log Writer
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement structured audit logging for all playbook actions and decisions.
**Acceptance Criteria:**
- [ ] `src/engine/audit-logger.ts` created
- [ ] Logs every action execution with timestamp, user, and result
- [ ] Logs all approval decisions
- [ ] Logs state transitions
- [ ] Writes to SQLite `audit_logs` table
- [ ] Audit log immutable (append-only)
- [ ] Export audit log to JSON/CSV
**Dependencies:** S0-010
**Tests Required:** Audit log write and query tests

---

### S1-013: Execution History Storage
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement execution history persistence and retrieval from SQLite.
**Acceptance Criteria:**
- [ ] `src/db/execution-repository.ts` created
- [ ] Save execution on start, update on completion
- [ ] Store: playbook ID, status, start/end time, context snapshot, result
- [ ] Query executions by playbook, date range, status
- [ ] Retrieve execution details by ID
- [ ] CLI command to list execution history
**Dependencies:** S0-010, S1-011
**Tests Required:** Repository CRUD tests

---

### S1-014: Engine Integration Tests
**Type:** Test
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Write comprehensive integration tests for the complete execution engine.
**Acceptance Criteria:**
- [ ] Test full L0 playbook execution
- [ ] Test full L1 playbook execution with read/write actions
- [ ] Test approval flows (approve, reject, timeout)
- [ ] Test error handling modes (halt, continue, skip)
- [ ] Test rollback execution
- [ ] Test execution resume after pause
- [ ] Test concurrent playbook execution
- [ ] All tests use in-memory DB and mock adapters
**Dependencies:** S1-011
**Tests Required:** Integration test suite with 10+ scenarios

---

## S2: Adapter Layer

**Goal:** Build vendor-agnostic adapter framework and implement core adapters for common SOC actions.
**Tickets:** 12
**Priority:** P1-P2 (enables real integrations)

### S2-001: Adapter Interface Definition
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Define the adapter contract/interface that all vendor adapters must implement.
**Acceptance Criteria:**
- [ ] `src/adapters/adapter-interface.ts` created
- [ ] Interface methods: `execute()`, `validate()`, `getCapabilities()`, `healthCheck()`
- [ ] Adapter metadata: name, version, vendor, supported actions
- [ ] Result types: `AdapterResult`, `AdapterError`
- [ ] Timeout and retry configuration per adapter
- [ ] Adapter interface documented
**Dependencies:** None
**Tests Required:** N/A (interface definition)

---

### S2-002: Adapter Registry
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement adapter registry to discover, load, and manage adapters.
**Acceptance Criteria:**
- [ ] `src/adapters/registry.ts` created
- [ ] Auto-discover adapters from `adapters/` directory
- [ ] Register adapters by name and action type
- [ ] Validate adapters implement interface
- [ ] Adapter lazy loading (load on first use)
- [ ] CLI command to list available adapters
**Dependencies:** S2-001
**Tests Required:** Registry tests with mock adapters

---

### S2-003: Mock Adapter Framework
**Type:** Infrastructure
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Create mock adapter framework for testing without real vendor APIs.
**Acceptance Criteria:**
- [ ] `src/adapters/mock/mock-adapter.ts` base class created
- [ ] Supports configurable success/failure responses
- [ ] Supports latency simulation
- [ ] Records all calls for test assertions
- [ ] Mock adapters for all core action types
- [ ] Documentation on creating mock adapters
**Dependencies:** S2-001
**Tests Required:** Mock adapter behavior tests

---

### S2-004: IP Block Adapter (Firewall)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement adapter for blocking IP addresses via firewall API.
**Acceptance Criteria:**
- [ ] `src/adapters/firewall/ip-block-adapter.ts` created
- [ ] Actions: `block_ip`, `unblock_ip`, `check_ip_status`
- [ ] Supports mock mode and real API mode
- [ ] Real mode supports common firewall APIs (Palo Alto, Fortinet, iptables)
- [ ] Handles API auth, rate limits, timeouts
- [ ] Returns structured result with block status
**Dependencies:** S2-001, S2-002
**Tests Required:** Unit tests with mock API, integration tests with mock adapter

---

### S2-005: Host Isolation Adapter (EDR)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement adapter for isolating hosts via EDR platform APIs.
**Acceptance Criteria:**
- [ ] `src/adapters/edr/host-isolation-adapter.ts` created
- [ ] Actions: `isolate_host`, `unisolate_host`, `get_isolation_status`
- [ ] Supports CrowdStrike Falcon API and Wazuh API
- [ ] Mock mode for testing
- [ ] Handles host ID resolution (hostname → EDR ID)
- [ ] Returns isolation status and timestamp
**Dependencies:** S2-001, S2-002
**Tests Required:** Unit tests with mock EDR API

---

### S2-006: Log Collection Adapter (SIEM)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement adapter for querying logs from SIEM platforms.
**Acceptance Criteria:**
- [ ] `src/adapters/siem/log-collection-adapter.ts` created
- [ ] Actions: `query_logs`, `get_events_by_id`
- [ ] Supports Elasticsearch/OpenSearch API
- [ ] Mock mode returns sample log events
- [ ] Supports time range and field filters
- [ ] Returns events in ECS format
**Dependencies:** S2-001, S2-002, S0-007
**Tests Required:** Unit tests with mock SIEM responses

---

### S2-007: VirusTotal Enrichment Adapter
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement adapter for enriching IOCs via VirusTotal API.
**Acceptance Criteria:**
- [ ] `src/adapters/enrichment/virustotal-adapter.ts` created
- [ ] Actions: `enrich_hash`, `enrich_domain`, `enrich_ip`, `enrich_url`
- [ ] Uses VirusTotal API v3
- [ ] Handles API key from config
- [ ] Respects rate limits
- [ ] Returns detection stats and threat labels
**Dependencies:** S2-001, S2-002, S0-008
**Tests Required:** Unit tests with mock VT responses

---

### S2-008: Process Tree Enrichment Adapter (EDR)
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Implement adapter for retrieving process tree data from EDR.
**Acceptance Criteria:**
- [ ] `src/adapters/edr/process-tree-adapter.ts` created
- [ ] Actions: `get_process_tree`, `get_process_details`
- [ ] Supports CrowdStrike and Wazuh
- [ ] Returns parent/child process relationships
- [ ] Includes command line, hashes, user context
- [ ] Mock mode returns sample process tree
**Dependencies:** S2-001, S2-002
**Tests Required:** Unit tests with mock EDR API

---

### S2-009: Notification Adapter (Slack/Email)
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Implement adapter for sending notifications to analysts.
**Acceptance Criteria:**
- [ ] `src/adapters/notification/notification-adapter.ts` created
- [ ] Actions: `send_slack_message`, `send_email`
- [ ] Slack webhook support
- [ ] SMTP email support (configurable server)
- [ ] Message templating with alert context
- [ ] Mock mode logs notifications without sending
**Dependencies:** S2-001, S2-002
**Tests Required:** Unit tests with mock Slack/SMTP

---

### S2-010: Adapter Error Handling
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement standardized error handling across all adapters.
**Acceptance Criteria:**
- [ ] `src/adapters/error-handler.ts` created
- [ ] Error types: `AuthError`, `TimeoutError`, `RateLimitError`, `NotFoundError`, `APIError`
- [ ] Retry logic with exponential backoff
- [ ] Graceful degradation on adapter failure
- [ ] Error details logged with context
- [ ] Circuit breaker for repeated failures
**Dependencies:** S2-001
**Tests Required:** Error handling tests for all error types

---

### S2-011: Adapter Configuration
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** S (< 2hr)
**Description:** Implement per-adapter configuration system for API keys, endpoints, and settings.
**Acceptance Criteria:**
- [ ] Adapters read config from `config.yml` or env vars
- [ ] Config schema: API keys, base URLs, timeouts, retry counts
- [ ] Adapter-specific config namespaced (e.g., `adapters.crowdstrike.api_key`)
- [ ] Config validation on adapter initialization
- [ ] Secrets never logged
**Dependencies:** S0-008, S2-001
**Tests Required:** Config loading tests per adapter

---

### S2-012: Adapter Integration Tests
**Type:** Test
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Write integration tests for all adapters using mock mode.
**Acceptance Criteria:**
- [ ] Test each adapter action with success scenario
- [ ] Test error handling (auth failure, timeout, rate limit)
- [ ] Test retry logic
- [ ] Test adapter registration and discovery
- [ ] Test concurrent adapter calls
- [ ] All tests use mock mode (no real API calls)
**Dependencies:** All S2 adapter tickets
**Tests Required:** Integration test suite covering all adapters

---

## S3: L2 Simulation Mode

**Goal:** Build L2 simulation engine that dry-runs write actions and builds approval queue for one-click execution.
**Tickets:** 11
**Priority:** P1-P2 (differentiating feature)

### S3-001: SimulationResult Type Definition
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** S (< 2hr)
**Description:** Define TypeScript types for simulation results distinct from execution results.
**Acceptance Criteria:**
- [ ] `src/types/simulation.ts` created
- [ ] `SimulationResult` type with fields: action, would_execute, impact_assessment, confidence, risk_score
- [ ] `SimulationContext` type with dry-run state
- [ ] Differentiates from `ExecutionResult`
- [ ] Includes DetectForge confidence metadata if available
**Dependencies:** S0-005
**Tests Required:** Type validation tests

---

### S3-002: L2 Simulation Executor
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** XL (8+hr)
**Description:** Implement L2 executor that simulates write actions without executing them.
**Acceptance Criteria:**
- [ ] `src/engine/executors/l2-executor.ts` created
- [ ] Executes read-only actions normally
- [ ] Simulates write actions (calls adapter in dry-run mode)
- [ ] Generates impact assessment per write action
- [ ] Stores simulations in approval queue
- [ ] Displays "would execute" summary to analyst
- [ ] Requires `--enable-l2` flag to activate
**Dependencies:** S1-001, S1-003, S1-005, S3-001
**Tests Required:** L2 executor tests with mock adapters in dry-run mode

---

### S3-003: Approval Queue Storage
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** M (2-4hr)
**Description:** Implement SQLite storage for pending L2 simulated actions awaiting approval.
**Acceptance Criteria:**
- [ ] `src/db/approval-queue-repository.ts` created
- [ ] Table schema: `approval_queue` (id, execution_id, action, context, justification, status, created_at)
- [ ] CRUD operations: create, get by ID, list pending, approve, reject
- [ ] Status values: `pending`, `approved`, `rejected`, `executed`, `expired`
- [ ] TTL for pending approvals (auto-expire after N hours)
**Dependencies:** S0-010, S3-001
**Tests Required:** Repository CRUD tests with in-memory DB

---

### S3-004: Dry-Run Mode for Adapters
**Type:** Feature
**Priority:** P0 (blocker)
**Estimate:** L (4-8hr)
**Description:** Add dry-run mode to all write action adapters to support L2 simulation.
**Acceptance Criteria:**
- [ ] All write adapters implement `dryRun` parameter
- [ ] Dry-run mode validates parameters without executing
- [ ] Returns simulated success/failure based on validation
- [ ] Estimates impact (e.g., "would block 1 IP address")
- [ ] Dry-run results distinguishable from real results
- [ ] Mock adapters support dry-run
**Dependencies:** S2-004, S2-005, S3-001
**Tests Required:** Dry-run tests for all write adapters

---

### S3-005: Impact Assessment Engine
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement impact assessment for simulated write actions to inform analyst decisions.
**Acceptance Criteria:**
- [ ] `src/engine/impact-assessor.ts` created
- [ ] Assesses blast radius (e.g., hosts affected, users impacted)
- [ ] Calculates risk score (1-10) based on action type and target
- [ ] Identifies dependencies (e.g., critical services on isolated host)
- [ ] Generates human-readable impact summary
- [ ] Uses asset criticality metadata if available
**Dependencies:** S3-001
**Tests Required:** Impact assessment tests for various action types

---

### S3-006: Automation Policy Enforcement
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement policy engine to enforce automation level constraints (L0/L1/L2).
**Acceptance Criteria:**
- [ ] `src/engine/policy-enforcer.ts` created
- [ ] Checks automation level per step against configured level
- [ ] Blocks L2 execution without `--enable-l2` flag
- [ ] Validates approval requirements per action
- [ ] Policy violations logged and prevent execution
- [ ] Override policy for admin users (configurable)
**Dependencies:** S1-001, S3-002
**Tests Required:** Policy enforcement tests with various levels

---

### S3-007: Confidence Scoring Display
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** S (< 2hr)
**Description:** Display DetectForge confidence scores in simulation results to inform decisions.
**Acceptance Criteria:**
- [ ] Extract `x-detectforge.confidence` from alert metadata
- [ ] Display confidence score with simulated action
- [ ] Color-code confidence (high=green, medium=yellow, low=red)
- [ ] Include detection provenance (which rule triggered)
- [ ] Fallback gracefully if confidence metadata missing
**Dependencies:** S0-007, S3-001
**Tests Required:** Confidence display tests with/without metadata

---

### S3-008: One-Click Execution from Queue
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement CLI command to approve and execute pending simulations from approval queue.
**Acceptance Criteria:**
- [ ] `runbookpilot approve <approval-id>` command
- [ ] Retrieves simulation from queue
- [ ] Executes action in L1 mode (real execution)
- [ ] Updates queue status to `executed`
- [ ] Logs approval and execution in audit log
- [ ] Supports bulk approve (multiple IDs)
**Dependencies:** S3-003, S3-002
**Tests Required:** Approval execution tests with mock queue

---

### S3-009: Simulation Metrics Collection
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Collect metrics on simulated actions for analyst review.
**Acceptance Criteria:**
- [ ] Track: total simulations, approval rate, average approval latency
- [ ] Track: action type distribution (what would have been executed)
- [ ] Track: false positive rate (approved then immediately rolled back)
- [ ] Store metrics in SQLite
- [ ] CLI command to display simulation metrics
**Dependencies:** S3-003, S3-008
**Tests Required:** Metrics collection tests

---

### S3-010: Simulation Audit Logging
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** S (< 2hr)
**Description:** Extend audit logging to capture all L2 simulation events.
**Acceptance Criteria:**
- [ ] Log simulation start/end with playbook context
- [ ] Log each simulated action with would-execute details
- [ ] Log approval/rejection decisions with approver
- [ ] Log one-click execution from queue
- [ ] Audit log distinguishes simulation from real execution
**Dependencies:** S1-012, S3-002
**Tests Required:** Audit log tests for simulation events

---

### S3-011: L2 Integration Tests
**Type:** Test
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Write comprehensive integration tests for L2 simulation mode.
**Acceptance Criteria:**
- [ ] Test full L2 playbook simulation
- [ ] Test approval queue population
- [ ] Test one-click execution from queue
- [ ] Test dry-run mode for all write adapters
- [ ] Test impact assessment accuracy
- [ ] Test policy enforcement (no execution without --enable-l2)
- [ ] Test concurrent simulations
**Dependencies:** S3-002, S3-008
**Tests Required:** Integration test suite with 8+ scenarios

---

## S4: Reference Runbooks & Integration

**Goal:** Build 3 end-to-end reference playbooks and integrate with DetectForge for alert ingestion.
**Tickets:** 14
**Priority:** P1-P2 (demonstrates value)

### S4-001: Reference Playbook 1 - LSASS Credential Dumping (L0)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Create reference playbook for LSASS credential dumping triage using L0 (manual checklist).
**Acceptance Criteria:**
- [ ] Playbook file: `playbooks/lsass-credential-dumping-l0.yml`
- [ ] Trigger: Sigma rule match for T1003.001
- [ ] Steps: Display alert summary, manual EDR investigation, manual VT hash lookup, manual asset criticality check
- [ ] Outputs: Enriched alert context for analyst decision
- [ ] Documentation: `docs/playbooks/lsass-credential-dumping.md`
- [ ] Works end-to-end with sample ECS alert
**Dependencies:** S1-011
**Tests Required:** E2E test with sample alert

---

### S4-002: Reference Playbook 2 - WMI Lateral Movement (L1)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** XL (8+hr)
**Description:** Create reference playbook for WMI lateral movement with semi-automated containment (L1).
**Acceptance Criteria:**
- [ ] Playbook file: `playbooks/wmi-lateral-movement-l1.yml`
- [ ] Trigger: Sigma rule match for T1047
- [ ] Steps: Auto-query EDR for process tree, auto-enrich with VT, prompt for host isolation, auto-log network connections, notify analyst
- [ ] Rollback: Un-isolate host if false positive
- [ ] Approval required for isolation action
- [ ] Documentation: `docs/playbooks/wmi-lateral-movement.md`
**Dependencies:** S1-011, S2-005, S2-007, S2-008, S2-009
**Tests Required:** E2E test with approval flow

---

### S4-003: Reference Playbook 3 - Cobalt Strike C2 (L2)
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** XL (8+hr)
**Description:** Create reference playbook for Cobalt Strike C2 beaconing with L2 simulation.
**Acceptance Criteria:**
- [ ] Playbook file: `playbooks/cobalt-strike-c2-l2.yml`
- [ ] Trigger: Suricata rule match for T1071.001
- [ ] Simulated actions: Block C2 domain, quarantine host, pull memory dump
- [ ] Approval request with full context and DetectForge confidence
- [ ] One-click execution path from approval queue
- [ ] Documentation: `docs/playbooks/cobalt-strike-c2.md`
**Dependencies:** S3-002, S3-008, S2-004, S2-005
**Tests Required:** E2E test with simulation and approval

---

### S4-004: DetectForge Webhook Receiver
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** L (4-8hr)
**Description:** Implement webhook endpoint to receive alerts from DetectForge.
**Acceptance Criteria:**
- [ ] `src/ingest/webhook-receiver.ts` created
- [ ] HTTP server listens on configurable port
- [ ] POST endpoint: `/api/v1/alerts`
- [ ] Validates `x-detectforge` metadata header
- [ ] Parses ECS alert JSON
- [ ] Triggers playbook execution based on ATT&CK technique
- [ ] Returns execution ID in response
**Dependencies:** S0-007, S1-011
**Tests Required:** Webhook integration tests with mock requests

---

### S4-005: ATT&CK Technique to Playbook Mapping
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement mapping system to match ATT&CK techniques to playbooks.
**Acceptance Criteria:**
- [ ] `src/engine/playbook-matcher.ts` created
- [ ] Mapping file: `config/technique-playbook-map.yml`
- [ ] Maps technique ID (e.g., T1003.001) to playbook file
- [ ] Supports multiple playbooks per technique
- [ ] Fallback to default playbook if no match
- [ ] CLI command to view mapping
**Dependencies:** S1-010
**Tests Required:** Mapping tests with various techniques

---

### S4-006: STDIN/File Alert Ingestion
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Support standalone mode where alerts are ingested from STDIN or file.
**Acceptance Criteria:**
- [ ] `runbookpilot run --input <file>` loads alert from JSON file
- [ ] `echo '{"alert": ...}' | runbookpilot run` reads from STDIN
- [ ] Validates alert against ECS schema
- [ ] Triggers playbook execution same as webhook
- [ ] Supports batch processing (multiple alerts in file)
**Dependencies:** S0-007, S1-011
**Tests Required:** STDIN/file ingestion tests

---

### S4-007: Docker Compose Integration (DetectForge + RunbookPilot)
**Type:** Infrastructure
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Create Docker Compose setup for integrated DetectForge + RunbookPilot demo.
**Acceptance Criteria:**
- [ ] `docker-compose.integration.yml` created
- [ ] Services: DetectForge, RunbookPilot, shared volume for configs
- [ ] DetectForge configured to send alerts to RunbookPilot webhook
- [ ] Network configuration for service communication
- [ ] Documentation: `docs/INTEGRATION_DEMO.md`
- [ ] `docker-compose up` starts full pipeline
**Dependencies:** S4-004, S0-012
**Tests Required:** Integration test with both services running

---

### S4-008: Trigger Condition Evaluation
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Implement trigger condition evaluator to filter which alerts execute playbooks.
**Acceptance Criteria:**
- [ ] `src/engine/trigger-evaluator.ts` created
- [ ] Evaluates trigger conditions from playbook (e.g., `alert.severity == 'critical'`)
- [ ] Supports operators: `==`, `!=`, `>`, `<`, `in`, `contains`, `matches`
- [ ] Supports boolean logic: `and`, `or`, `not`
- [ ] Skips playbook execution if conditions not met
- [ ] Logs trigger evaluation result
**Dependencies:** S1-010
**Tests Required:** Trigger evaluation tests with various conditions

---

### S4-009: Playbook Metadata Enrichment
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** S (< 2hr)
**Description:** Enrich playbooks with metadata for discovery and analytics.
**Acceptance Criteria:**
- [ ] Playbook metadata: name, description, version, author, ATT&CK techniques, MITRE D3FEND tactics
- [ ] Metadata displayed in `runbookpilot list` output
- [ ] Metadata searchable (e.g., find playbooks by technique)
- [ ] Metadata included in execution logs
**Dependencies:** S0-004
**Tests Required:** Metadata parsing tests

---

### S4-010: Playbook Library CLI
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Implement CLI commands for managing playbook library.
**Acceptance Criteria:**
- [ ] `runbookpilot list` - list all playbooks with metadata
- [ ] `runbookpilot show <playbook>` - display playbook details
- [ ] `runbookpilot search <term>` - search playbooks by keyword/technique
- [ ] `runbookpilot validate <playbook>` - validate playbook syntax
- [ ] Output formatted as table or JSON
**Dependencies:** S1-010, S4-009
**Tests Required:** CLI command tests

---

### S4-011: Alert Context Enrichment Pipeline
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Build enrichment pipeline to augment alerts with additional context before playbook execution.
**Acceptance Criteria:**
- [ ] `src/engine/enrichment-pipeline.ts` created
- [ ] Enrichments: GeoIP lookup, asset inventory lookup, user directory lookup, threat intel lookup
- [ ] Enrichments added to execution context
- [ ] Enrichment failures don't block execution
- [ ] Configurable enrichment sources
**Dependencies:** S1-002
**Tests Required:** Enrichment pipeline tests with mock sources

---

### S4-012: Execution Timeout and Cancellation
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Implement execution timeout and manual cancellation support.
**Acceptance Criteria:**
- [ ] Global execution timeout configurable per playbook
- [ ] Execution auto-cancelled on timeout
- [ ] `runbookpilot cancel <execution-id>` CLI command
- [ ] Cancellation triggers rollback if configured
- [ ] Cancellation logged in audit log
- [ ] In-flight adapter calls gracefully terminated
**Dependencies:** S1-011, S1-009
**Tests Required:** Timeout and cancellation tests

---

### S4-013: Reference Playbook Documentation
**Type:** Documentation
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Write comprehensive documentation for all reference playbooks.
**Acceptance Criteria:**
- [ ] Each playbook has dedicated doc: `docs/playbooks/<name>.md`
- [ ] Documentation includes: threat description, playbook logic, automation level rationale, rollback strategy
- [ ] Sample alert inputs provided
- [ ] Expected execution outcomes documented
- [ ] Customization guidance for SOC teams
**Dependencies:** S4-001, S4-002, S4-003
**Tests Required:** N/A (documentation)

---

### S4-014: Integration Test Suite
**Type:** Test
**Priority:** P1 (must-have)
**Estimate:** XL (8+hr)
**Description:** Write comprehensive integration tests for all reference playbooks and DetectForge integration.
**Acceptance Criteria:**
- [ ] E2E test for each reference playbook (3 total)
- [ ] E2E test for webhook ingestion
- [ ] E2E test for STDIN ingestion
- [ ] E2E test for technique-to-playbook mapping
- [ ] E2E test for Docker Compose integration
- [ ] All tests use mock adapters and in-memory DB
- [ ] Tests verify audit logs and execution history
**Dependencies:** All S4 tickets
**Tests Required:** Integration test suite with 8+ scenarios

---

## S5: Dashboard & Polish

**Goal:** Build metrics dashboard, LLM analyst assistant, and polish for portfolio-ready release.
**Tickets:** 10
**Priority:** P2-P3 (polish and differentiation)

### S5-001: Execution Metrics Collection
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Collect and aggregate execution metrics for dashboard display.
**Acceptance Criteria:**
- [ ] `src/metrics/collector.ts` created
- [ ] Metrics: total executions, success rate, failure rate, avg execution time
- [ ] MTTD/MTTR calculations (Mean Time To Detect/Respond)
- [ ] Metrics aggregated by playbook, technique, automation level
- [ ] Metrics stored in SQLite with timestamps
- [ ] Metrics API for dashboard consumption
**Dependencies:** S1-013
**Tests Required:** Metrics collection and aggregation tests

---

### S5-002: Approval Latency Metrics
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** S (< 2hr)
**Description:** Track time from simulation to human approval for L2 actions.
**Acceptance Criteria:**
- [ ] Calculate latency: simulation timestamp → approval timestamp
- [ ] Track average, median, P95 latency
- [ ] Break down by action type and playbook
- [ ] Identify bottleneck steps
- [ ] Metrics queryable via CLI
**Dependencies:** S3-003, S5-001
**Tests Required:** Latency calculation tests

---

### S5-003: Playbook Coverage Metrics
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Track which ATT&CK techniques have playbook coverage.
**Acceptance Criteria:**
- [ ] Calculate coverage: techniques with playbooks / total techniques in use
- [ ] Identify gaps (techniques without playbooks)
- [ ] Track playbook usage frequency per technique
- [ ] Suggest techniques needing playbooks
- [ ] CLI command to display coverage report
**Dependencies:** S4-005, S5-001
**Tests Required:** Coverage calculation tests

---

### S5-004: CLI Metrics Dashboard
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** L (4-8hr)
**Description:** Build CLI-based metrics dashboard for SOC analysts.
**Acceptance Criteria:**
- [ ] `runbookpilot metrics` command displays dashboard
- [ ] Sections: Execution Stats, MTTD/MTTR, Approval Latency, Playbook Coverage
- [ ] Time range filters (24h, 7d, 30d, all time)
- [ ] Formatted as ASCII tables and charts
- [ ] Export metrics to JSON/CSV
- [ ] Refresh in real-time with `--watch` flag
**Dependencies:** S5-001, S5-002, S5-003
**Tests Required:** Dashboard rendering tests

---

### S5-005: Approval Queue UI (CLI)
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** M (2-4hr)
**Description:** Build CLI interface for reviewing and approving pending L2 simulations.
**Acceptance Criteria:**
- [ ] `runbookpilot queue` command lists pending approvals
- [ ] Displays: ID, playbook, action, impact, confidence, age
- [ ] Interactive mode: select approval and approve/reject
- [ ] Bulk operations: approve all, reject all
- [ ] Filtering: by playbook, technique, risk score
- [ ] Pagination for large queues
**Dependencies:** S3-003, S3-008
**Tests Required:** Queue UI tests with mock data

---

### S5-006: LLM Enrichment Summarization
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** L (4-8hr)
**Description:** Integrate LLM to summarize enrichment data for analyst review.
**Acceptance Criteria:**
- [ ] `src/llm/summarizer.ts` created
- [ ] Uses OpenRouter API (same as DetectForge)
- [ ] Summarizes: process tree, VT results, log queries, network connections
- [ ] Generates 2-3 sentence summary per enrichment
- [ ] Highlights key findings and anomalies
- [ ] Graceful fallback when LLM unavailable
**Dependencies:** S0-008, S4-011
**Tests Required:** Summarization tests with mock LLM responses

---

### S5-007: LLM Playbook Suggestion
**Type:** Feature
**Priority:** P3 (nice-to-have)
**Estimate:** L (4-8hr)
**Description:** Use LLM to suggest playbooks based on alert context when no technique match exists.
**Acceptance Criteria:**
- [ ] `src/llm/playbook-suggester.ts` created
- [ ] Analyzes alert fields and enrichment data
- [ ] Suggests relevant playbooks from library
- [ ] Provides justification for suggestion
- [ ] Analyst can accept/reject suggestion
- [ ] Fallback to default playbook if LLM unavailable
**Dependencies:** S4-005, S5-006
**Tests Required:** Suggestion tests with various alert types

---

### S5-008: LLM Investigation Notes
**Type:** Feature
**Priority:** P3 (nice-to-have)
**Estimate:** M (2-4hr)
**Description:** Auto-generate investigation notes from playbook execution for case documentation.
**Acceptance Criteria:**
- [ ] `src/llm/note-generator.ts` created
- [ ] Generates notes from execution context and results
- [ ] Includes: timeline, actions taken, findings, recommendations
- [ ] Formatted as markdown
- [ ] Notes saved to execution record
- [ ] CLI command to export notes
**Dependencies:** S5-006, S1-013
**Tests Required:** Note generation tests

---

### S5-009: Error Handling Polish
**Type:** Feature
**Priority:** P1 (must-have)
**Estimate:** M (2-4hr)
**Description:** Comprehensive error handling polish for production readiness.
**Acceptance Criteria:**
- [ ] All errors have clear, actionable messages
- [ ] Network failures handled with retries
- [ ] API rate limits handled gracefully
- [ ] Auth failures provide remediation steps
- [ ] Partial failures don't crash execution
- [ ] All errors logged with context
- [ ] User-facing errors sanitized (no stack traces)
**Dependencies:** All previous sprints
**Tests Required:** Error scenario tests

---

### S5-010: Performance Optimization
**Type:** Feature
**Priority:** P2 (should-have)
**Estimate:** L (4-8hr)
**Description:** Optimize performance for high-volume alert processing.
**Acceptance Criteria:**
- [ ] Parallel execution of independent steps
- [ ] Adapter call pooling and caching
- [ ] Database query optimization (indexes)
- [ ] Memory usage profiling and reduction
- [ ] Execution time < 30s for typical playbook
- [ ] Supports 100+ concurrent executions
- [ ] Load testing results documented
**Dependencies:** All previous sprints
**Tests Required:** Performance benchmarks and load tests

---

## Sprint Summary

### Ticket Breakdown by Sprint
- **S0 (Foundation):** 12 tickets
- **S1 (Execution Engine):** 14 tickets
- **S2 (Adapter Layer):** 12 tickets
- **S3 (L2 Simulation):** 11 tickets
- **S4 (Runbooks & Integration):** 14 tickets
- **S5 (Dashboard & Polish):** 10 tickets

**Total:** 73 tickets

### Priority Distribution
- **P0 (Blocker):** 18 tickets - Core infrastructure and critical path
- **P1 (Must-Have):** 38 tickets - Essential features for MVP
- **P2 (Should-Have):** 15 tickets - Important for completeness
- **P3 (Nice-to-Have):** 2 tickets - Polish and differentiation

### Estimated Timeline
Assuming DetectForge velocity (3 parallel agents, ~2 weeks per sprint):
- **S0:** 1 week (foundation work, can parallelize)
- **S1:** 2 weeks (core engine, sequential dependencies)
- **S2:** 1.5 weeks (adapters parallelizable)
- **S3:** 1.5 weeks (builds on S1/S2)
- **S4:** 2 weeks (reference playbooks, integration)
- **S5:** 1 week (polish, metrics, LLM features)

**Total:** 6-8 weeks to portfolio-ready release

### Testing Strategy
- **Unit Tests:** Every feature ticket requires unit tests
- **Integration Tests:** Each sprint ends with integration test ticket
- **E2E Tests:** S4 includes full end-to-end testing
- **Target Coverage:** 80%+ (matching DetectForge standard)

### Key Dependencies
1. **S0 must complete first** - Foundation for everything
2. **S1 → S2 → S3** - Sequential core feature progression
3. **S4 depends on S1-S3** - Integration requires all automation levels
4. **S5 depends on all** - Polish requires complete system

### Success Metrics
- 516+ passing tests (match DetectForge quality bar)
- 3 working reference playbooks (L0, L1, L2)
- DetectForge integration functional
- MTTD/MTTR measurably improved vs manual runbooks
- Portfolio-ready documentation and demo

---

## Next Steps

1. **Initialize S0:** Run S0-001 to scaffold project
2. **Parallel S0 Work:** S0-002 through S0-012 can be done concurrently
3. **S0 Gate:** Complete all S0 tickets before moving to S1
4. **Iterate:** Follow DetectForge pattern of committing after each sprint
5. **Test Continuously:** `bun run test` after each ticket

**Ready to start with S0-001!**

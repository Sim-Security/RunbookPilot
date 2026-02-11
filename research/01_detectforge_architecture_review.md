# DetectForge Complete Architecture & Integration Analysis Report

## Executive Summary

DetectForge is a production-grade, AI-powered detection rule generation engine that transforms threat intelligence reports into validated detection rules across three formats (Sigma, YARA, Suricata). The system is architected as a seven-stage pipeline with clear module boundaries, comprehensive validation, and transparent quality metrics.

**Key metrics:**
- **78 TypeScript source files** across 12 major modules
- **50 unit test files** with 516 passing tests
- **7-stage pipeline** from ingestion through reporting
- **3 rule formats** with format-specific validators and generators
- **~7,153 lines of source code** (excluding tests and node_modules)

---

## 1. Seven-Stage Pipeline

```
Report (PDF/HTML/MD)
    → [1] INGESTION → ThreatReport (normalized, sectioned)
    → [2] EXTRACTION → ExtractedIOC[], ExtractedTTP[], AttackMappingResult[]
    → [3] GENERATION → SigmaRule[], YaraRule[], SuricataRule[]
    → [4] VALIDATION → ValidationResult (syntax + schema checks)
    → [5] ENRICHMENT → RuleDocumentation, FalsePositiveScenarios, CoverageGaps
    → [6] TESTING → QualityReport, CoverageMetrics, ValidationSummary
    → [7] REPORTING → JSON, Markdown, SARIF, ATT&CK Navigator, Rule Files
```

---

## 2. Core Data Types (RunbookPilot Integration Points)

### GeneratedRule (discriminated union)
```typescript
{
  format: 'sigma' | 'yara' | 'suricata',
  sigma?: SigmaRule,
  yara?: YaraRule,
  suricata?: SuricataRule,
  sourceReportId: string,
  sourceTtp?: string,
  attackTechniqueId?: string,   // e.g., "T1059.001"
  attackTactic?: string,         // e.g., "Execution"
  confidence: 'high' | 'medium' | 'low',
  documentation?: RuleDocumentation,
  validation: ValidationResult,
}
```

### RuleDocumentation
```typescript
{
  whatItDetects: string,
  howItWorks: string,
  attackMapping: { techniqueId, techniqueName, tactic, platform },
  falsePositives: FalsePositiveScenario[],
  coverageGaps: string[],
  recommendedLogSources: string[],
  tuningRecommendations: string[],
}
```

### PipelineReport (full output)
```typescript
{
  metadata: { generatedAt, detectforgeVersion, inputFile, processingTimeMs },
  extraction: { iocs: ExtractedIOC[], ttps: ExtractedTTP[], attackMappings: AttackMappingResult[] },
  rules: GeneratedRule[],
  validation: { totalRules, validRules, invalidRules, passRate },
  quality?: QualityReport,
  coverage?: CoverageMetrics,
  cost: { totalUsd, byOperation: Record<string, number> },
}
```

---

## 3. AI Integration Architecture

### Three-Tier Model Selection
| Tier | Model | Use Cases |
|------|-------|-----------|
| fast | google/gemini-2.0-flash-001 | IOC extraction, classification |
| standard | anthropic/claude-3.5-haiku | TTP extraction, ATT&CK mapping, documentation |
| quality | anthropic/claude-sonnet-4 | Rule generation, complex reasoning |

- OpenRouter API integration
- Zod schema validation on all AI responses
- Exponential backoff retry (3 retries, 1s-30s)

---

## 4. Output Formats

| Format | File | Purpose |
|--------|------|---------|
| JSON | reports/summary.json | Machine-readable PipelineReport |
| Markdown | reports/report.md | Human-readable summary |
| SARIF | reports/detectforge.sarif | GitHub Advanced Security |
| ATT&CK Navigator | reports/coverage-navigator.json | Visual coverage heatmap |
| Rule Files | rules/*.yml / *.yar / *.rules | Individual exports |

---

## 5. RunbookPilot Integration Checklist

### What RunbookPilot needs from each rule:
1. **Rule identification:** rule.sigma?.id, rule.attackTechniqueId, rule.attackTactic
2. **Response context:** documentation.whatItDetects, documentation.falsePositives[], documentation.recommendedLogSources
3. **Confidence signals:** rule.confidence, rule.validation
4. **Operational metadata:** rule.sourceReportId, rule.sourceTtp

### Integration Options:
- **Option A:** Direct JSON — read PipelineReport from summary.json
- **Option B:** Event-driven — subscribe to ruleGenerated events
- **Type sharing:** Import from @detectforge/types or copy interfaces

---

## 6. Sprint Status
| Sprint | Status | Deliverables |
|--------|--------|-------------|
| S0 | COMPLETE | Foundation, types, utilities |
| S1 | PARTIAL | ATT&CK data, SigmaHQ corpus |
| S2 | COMPLETE | Ingestion, extraction |
| S3 | IN PROGRESS | Generators + validators (code done, tests pending) |
| S4-S7 | PENDING | Documentation, testing, CLI, portfolio polish |

---

## 7. Tech Stack
- Runtime: Bun + TypeScript (strict mode)
- Testing: vitest (80% coverage threshold)
- Key deps: commander, yaml, zod, cheerio, pdf-parse, chalk, ora
- Path aliases: @ → src/

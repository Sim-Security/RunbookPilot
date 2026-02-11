# SOAR & Runbook Automation Competitive Analysis (2024-2026)

**Prepared for:** RunbookPilot Project Planning
**Date:** February 10, 2026
**Scope:** Exhaustive market research covering SOAR platforms, SOC workflow analysis, market gaps, technology trends, and portfolio differentiation strategy.

---

## Table of Contents

1. [Major SOAR Platforms](#1-major-soar-platforms-2024-2026)
2. [Emerging AI-Native Players](#2-emerging-ai-native-players-2025-2026)
3. [Market Gaps & Whitespace](#3-market-gaps--whitespace)
4. [SOC Analyst Workflow Research](#4-soc-analyst-workflow-research)
5. [Technology Trends (2025-2026)](#5-technology-trends-2025-2026)
6. [Portfolio Differentiation Strategy](#6-portfolio-differentiation-strategy)
7. [Competitive Positioning Matrix](#7-competitive-positioning-matrix)
8. [Strategic Recommendations for RunbookPilot](#8-strategic-recommendations-for-runbookpilot)
9. [Sources](#9-sources)

---

## 1. Major SOAR Platforms (2024-2026)

### 1.1 Palo Alto Cortex XSOAR / XSIAM / AgentiX

| Dimension | Details |
|-----------|---------|
| **Pricing** | Enterprise license ~$250,000/year. Subscription-based, per-user + incident volume. Heavy discounting for renewals (reportedly $60K-$100K reductions in year 2+). 30-day free trial available. |
| **Target Market** | Large enterprises, Fortune 500 SOCs. Increasingly pushing customers toward XSIAM as the unified platform. |
| **Key Features** | 900+ prebuilt integrations and automation packs; visual playbook editor (code-free); virtual war room for collaboration; ChatOps/CLI investigation; 1,000+ security actions for DIY playbooks. |
| **AI/ML Capabilities** | Cortex AgentiX (launched Oct 2025) -- next-gen agentic AI platform built on XSOAR. Claims: 98% reduction in MTTR, 75% less manual work. Trained on 1.2B playbook executions. Prebuilt agents for threat intel, email, endpoint, network, cloud, IT workflows. No-code GenAI builder with role-based guardrails and full auditability. |
| **Strengths** | Largest integration ecosystem in SOAR; aggressive investment in agentic AI; XSIAM convergence unifies SIEM + XDR + SOAR + TIP + exposure management. XSIAM surpassed $1B cumulative bookings in 2025 -- fastest-growing product in Palo Alto history. |
| **Weaknesses** | Extremely expensive for SMBs; vendor lock-in to Palo Alto ecosystem; complexity of migration from XSOAR standalone to XSIAM; steep learning curve. |
| **Integration Ecosystem** | 1,000+ prebuilt integrations via XSOAR Marketplace. |

**Key 2026 Development:** Cortex AgentiX available now in Cortex Cloud and XSIAM; standalone platform expected early 2026. Palo Alto is positioning toward the "Autonomous SOC" vision.

### 1.2 Splunk SOAR (Cisco)

| Dimension | Details |
|-----------|---------|
| **Pricing** | Subscription-based, varies by deployment size. Broader Splunk pricing: $1,800-$18,000/year for 1-10 GB/day. SOAR now bundled into Splunk Enterprise Security Premier Edition. |
| **Target Market** | Mid-to-large enterprises; existing Splunk/Cisco customers. |
| **Key Features** | Splunk ES 8.2 combines SOAR, TIP, UEBA, and SIEM into unified Essentials and Premier editions. Premier includes SOAR licenses no longer limited to named users. AI Playbook Authoring translates natural language into functional, tested SOAR playbooks. |
| **AI/ML Capabilities** | AI Playbook Authoring (natural language to playbook); Cisco introduced agentic AI-powered solutions powered by Splunk in Oct 2025. |
| **Strengths** | Deep integration with Splunk SIEM (largest SIEM market share); Cisco's $28B acquisition (March 2024) brings massive R&D resources; unified ES Premier eliminates tool-switching between SOAR/UEBA/SIEM. |
| **Weaknesses** | Ingestion-based pricing model is expensive at scale; post-acquisition uncertainty about product direction; heavy Splunk ecosystem dependency; SOAR capabilities historically lagged behind XSOAR. |
| **Integration Ecosystem** | Hundreds of apps via Splunkbase; broad Cisco security portfolio integration. |

### 1.3 Tines

| Dimension | Details |
|-----------|---------|
| **Pricing** | Subscription tiers by user count + features. **Community Edition: free forever** -- up to 3 Stories, nearly all features of paid version. Enterprise pricing custom. Updated packaging in June 2025. |
| **Target Market** | Security teams of all sizes; strong appeal to mid-market. Emphasizes accessibility for non-technical users. |
| **Key Features** | Drag-and-drop workflow builder; no-code automation; built as an "integrator, not on integrations" (connect to any API); case management for investigations; ML-based alert classification to reduce false positives. |
| **AI/ML Capabilities** | AI workflow orchestration with natural language, no-code, low-code, or custom code options. ML component for distinguishing genuine alerts from false positives. |
| **Strengths** | Fastest time-to-value (minutes, not weeks); free Community Edition creates strong bottom-up adoption; agnostic -- connects to any API without vendor-specific integrations; excellent UX/design. |
| **Weaknesses** | Community Edition limited to 3 Stories; less battle-tested than XSOAR/Splunk at Fortune 500 scale; smaller integration marketplace compared to established players. |
| **Integration Ecosystem** | API-first: connects to any tool with an API. Growing library of community-shared Stories. |

### 1.4 Swimlane Turbine

| Dimension | Details |
|-----------|---------|
| **Pricing** | Custom enterprise pricing. Subscription model with free trial available. |
| **Target Market** | Enterprises and MSSPs; emphasizes "beyond traditional SOAR." |
| **Key Features** | AI-enabled low-code automation; end-to-end SOC solutions for phishing triage and alert management; customizable multi-vendor TIP; robust case management; real-time dashboards. Can execute 25 million actions/day, 17x faster than alternatives. |
| **AI/ML Capabilities** | Agentic AI automation platform (Turbine). Claims 240% ROI in year 1, additional 20% efficiency gains with AI on top of automation. |
| **Strengths** | Exceptional performance (25M actions/day); strong MSSP/multi-tenant support; named in SANS SOC Survey 2025 results; good ROI metrics. |
| **Weaknesses** | Opaque pricing; less name recognition than Palo Alto/Splunk; competing in increasingly crowded "AI-native" positioning. |
| **Integration Ecosystem** | Multi-vendor integrations; Microsoft partnership. |

### 1.5 Torq Hyperautomation / HyperSOC

| Dimension | Details |
|-----------|---------|
| **Pricing** | Custom enterprise pricing. Subscription-based by workflows/integrations/actions. |
| **Target Market** | Enterprise SOCs, MSSPs, MDR providers. Positioned as "beyond SOAR." |
| **Key Features** | No-code platform; 200+ preconfigured connectors (XDR, IAM, EDR, ticketing, cloud); HyperSOC 2o with Multi-Agent System (MAS); native MCP support. |
| **AI/ML Capabilities** | **Socrates** -- agentic AI SOC Analyst (OmniAgent) coordinating: Runbook Agent (plans/adapts incident response runbooks), Investigation Agent (deep-dive investigations in seconds), Remediation Agent (executes with verifiable outcomes). Claims 95% of Tier-1 alerts resolved without human involvement. Acquired Revrod for multi-agent RAG. |
| **Strengths** | Most aggressive AI/agentic vision; $140M Series D at $1.2B valuation (early 2026); strong MAS architecture; built for multi-tenant MSSP environments; validated by IDC. |
| **Weaknesses** | Premium pricing; aggressive automation claims may face regulatory pushback; still proving enterprise reliability at scale. |
| **Integration Ecosystem** | 200+ connectors. AI-generated integrations in seconds. |

### 1.6 Shuffle (Open Source)

| Dimension | Details |
|-----------|---------|
| **Pricing** | **Free (open source)** with unlimited workflows, apps, and users. On-prem Enterprise plan starts at $960/month for 8 CPU cores. Cloud option available. |
| **Target Market** | Small-to-medium security teams; organizations that already have a SIEM and need a dedicated automation engine. |
| **Key Features** | Visual workflow editor; 200+ plug-and-play apps built on OpenAPI standard; 11,000+ endpoints for app building; community-driven integration library. |
| **AI/ML Capabilities** | Limited native AI/ML. Relies on integrations with external AI services. |
| **Strengths** | Truly free and open source; integrates well with other OSS tools (Wazuh, TheHive); uses OpenAPI standard for universal compatibility; fastest path from zero to automation for small teams. |
| **Weaknesses** | ~1.9K GitHub stars (niche adoption); performance constrained by server capacity; limited documentation; no native AI capabilities; community support only on free tier. |
| **Integration Ecosystem** | 200+ apps via OpenAPI. |

### 1.7 TheHive 5 + Cortex (StrangeBee)

| Dimension | Details |
|-----------|---------|
| **Pricing** | **Freemium model.** Community license: free for personal, educational, and basic commercial use. Gold and Platinum paid tiers (yearly subscription). 14-day Platinum trial included. Read-only users are free. Source code no longer publicly available (NDA required for review). |
| **Target Market** | SOCs, CERTs, CSIRTs. Strong adoption among incident response teams globally. |
| **Key Features** | TheHive: case/task management, alert triage from SIEMs, investigation templates. Cortex: 100+ analyzers (VirusTotal, Joe Sandbox, DomainTools, Shodan, etc.), active response via responders, multi-tenancy with RBAC, caching to avoid redundant analysis. |
| **AI/ML Capabilities** | Minimal native AI. Cortex analyzers provide enrichment but not AI-driven decision-making. |
| **Strengths** | Proven incident response platform; 52 releases since 2016; strong community trust; excellent observable analysis via Cortex. |
| **Weaknesses** | TheHive 5 shifted from fully open source to "freemium/private source" -- source code no longer publicly available; transitions to read-only after 14-day trial; automation capabilities weaker than pure SOAR platforms; no native AI/ML. |
| **Integration Ecosystem** | 100+ Cortex analyzers; integrates with MISP, Sigma, and other open-source tools. |

### 1.8 Google Security Operations (formerly Chronicle SOAR / Siemplify)

| Dimension | Details |
|-----------|---------|
| **Pricing** | Custom enterprise pricing, bundled with Google Security Operations. Core package includes 700+ parsers, 300+ SOAR integrations, 12 months hot data retention, detection engine with 1,000 single-event + 75 multi-event rules. |
| **Target Market** | Large enterprises; Google Cloud customers; organizations wanting petabyte-scale security analytics. |
| **Key Features** | Full SOAR with 300+ integrations; sub-second search across petabytes; automated playbooks; case wall with auto-documentation; AI-powered runbooks using Model Context Protocol (MCP). |
| **AI/ML Capabilities** | Gemini-powered AI runbooks for proactive threat hunting; Google SecOps Alert Triage and Investigation Agent (public preview); MCP integration for automated IOC blocking. |
| **Strengths** | Google-scale infrastructure; Gemini AI integration; named Leader in 2025 Gartner Magic Quadrant for SIEM; massive data retention at competitive pricing. |
| **Weaknesses** | Requires Google Cloud commitment; complex migration; less mature SOAR capabilities compared to dedicated players; pricing opacity. |
| **Integration Ecosystem** | 300+ SOAR integrations, 700+ parsers. |

### 1.9 IBM QRadar SOAR (formerly Resilient)

| Dimension | Details |
|-----------|---------|
| **Pricing** | Subscription-based per user or per incident volume. Cloud or on-premises. Described as "moderately expensive but affordable compared to other SOAR options." |
| **Target Market** | Regulated industries (finance, healthcare, government); organizations needing privacy compliance automation. |
| **Key Features** | Red Dot Design Award-winning Playbook Designer (dynamic, low-code); support for 180+ privacy regulations worldwide; breach response automation; unlimited product connections. |
| **AI/ML Capabilities** | Dynamic playbooks with conditional logic; AI integration through IBM watsonx. Less aggressive AI positioning than competitors. |
| **Strengths** | Best-in-class breach/privacy compliance (180+ regulations); proven in regulated industries; strong case management; good UX (design award-winning). |
| **Weaknesses** | IBM's strategic direction unclear after selling QRadar SIEM to Palo Alto; slower innovation pace; less AI/ML investment than competitors. |
| **Integration Ecosystem** | Unlimited integrations; strong ITSM connectivity. |

### 1.10 Microsoft Sentinel SOAR (Logic Apps + Playbooks)

| Dimension | Details |
|-----------|---------|
| **Pricing** | Sentinel: ~$5/GB ingested. SOAR playbooks: Logic Apps consumption-based pricing (per execution, charged separately). Minimal cost per playbook run unless executed frequently. |
| **Target Market** | Microsoft/Azure-native organizations; the broadest addressable market of any SOAR due to Microsoft's installed base. |
| **Key Features** | Playbooks built on Azure Logic Apps; prebuilt/tested playbook templates; automated + manual trigger options; 300+ connectors via Logic Apps; migration to Microsoft Defender portal by March 2027. |
| **AI/ML Capabilities** | Microsoft Copilot for Security integration; natural language queries; AI-assisted incident investigation; triage enrichment with threat intelligence. |
| **Strengths** | Lowest barrier to entry for Microsoft shops; pay-per-execution model scales from tiny to massive; Azure Logic Apps provides enterprise-grade reliability; Copilot for Security adds AI layer. |
| **Weaknesses** | SOAR capabilities are less mature than dedicated platforms; Logic Apps workflow designer is less intuitive for security workflows specifically; cost unpredictability with consumption pricing; Azure lock-in. |
| **Integration Ecosystem** | 300+ Logic Apps connectors; deep Microsoft 365/Defender/Entra integration. |

### 1.11 Fortinet FortiSOAR

| Dimension | Details |
|-----------|---------|
| **Pricing** | Subscription-based per users/features. On-premises or cloud. No free version but free trial available. |
| **Target Market** | Fortinet ecosystem customers; mid-to-large enterprises. |
| **Key Features** | 350+ security product integrations, 3,000+ actions; case management; TIP; workflow automation; FortiAI with natural language and generative AI guidance. |
| **AI/ML Capabilities** | FortiAI integration using natural language and generative AI to guide analyst activities within FortiSOAR. |
| **Strengths** | 2025 Gartner Peer Insights Customers' Choice for SOAR (excelled in all categories); tight Fortinet Security Fabric integration; strong breadth of integrations. |
| **Weaknesses** | Best value within Fortinet ecosystem -- less compelling standalone; FortiAI less advanced than CrowdStrike/Torq agentic approaches. |
| **Integration Ecosystem** | 350+ products, 3,000+ actions. |

---

## 2. Emerging AI-Native Players (2025-2026)

These are NOT traditional SOAR platforms but represent the direction the market is heading. Critical competitive context for RunbookPilot.

### 2.1 CrowdStrike Charlotte Agentic SOAR

- **Launched:** November 5, 2025
- **Architecture:** Orchestration layer of the Falcon Agentic Security Platform
- **Key Innovation:** Charlotte AI AgentiX -- first no-code platform for building, testing, deploying trusted security agents
- **Agents Available:** Exposure Prioritization, Malware Analysis, Hunt, Correlation Rule Generation, Search Analysis, Workflow Generation
- **Capabilities:** Natural language + drag-and-drop; guardrails and missions; unified case management in Falcon Next-Gen SIEM
- **Significance:** CrowdStrike is building the "agentic security workforce" -- AI agents that reason, decide, and act in real time

### 2.2 Dropzone AI

- **Funding:** $37M Series B (2025); 11x ARR growth in 2025
- **Approach:** World's first autonomous AI SOC Analyst
- **Capabilities:** Investigates every alert in under 10 minutes; 60+ tool integrations; LLM-based reasoning (not rule-based); contextual memory for false positive reduction
- **2026 Roadmap:** Expanding from single AI SOC Analyst to multi-agent architecture: AI Threat Hunter, AI Detection Engineer, AI Forensics Analyst, AI Threat Intelligence Analyst, AI Security Data Architect
- **Customers:** 300+ organizations including Datadog, Netflix, Stripe, UiPath, Zapier
- **Significance:** Proves the market for AI-native investigation without traditional playbooks

### 2.3 Radiant Security

- **Approach:** AI SOC platform automating 100% of alerts regardless of source, complexity, or novelty
- **Capabilities:** 100+ integrations; unlimited log retention; zero vendor lock-in; integrated log management at fraction of SIEM cost
- **Pricing:** Transparent/predictable; claims 85% log cost reduction vs. traditional SIEMs
- **Significance:** Targets the cost problem -- making AI SOC capabilities affordable

### 2.4 BlinkOps

- **Funding:** $50M raised (July 2025); $100M+ total
- **Approach:** Agentic Security Automation Platform (ASAP) -- explicitly "beyond SOAR"
- **Capabilities:** No-code Security Agent Builder; 150+ pre-built security micro-agents; 8,000+ prebuilt workflows; 30,000 API actions
- **Recognition:** Fortune 2026 Cyber 60 List
- **Significance:** Largest workflow library; strong no-code positioning for non-technical practitioners

### 2.5 Tracecat (Open Source, AI-Native)

- **Founded:** 2024 (Y Combinator W24)
- **Approach:** Open-source, AI-native alternative to Tines/Splunk SOAR
- **Capabilities:** YAML-based templates; no-code UI; built-in lookup tables + case management; AI-assisted labeling, summarization, enrichment
- **Target:** Understaffed small-to-mid-sized teams
- **Users:** Datadog, Netflix, Stripe (reportedly)
- **Significance:** Most direct open-source competitor to RunbookPilot's vision. Cloud-agnostic, Docker-deployable.

### 2.6 D3 Security Smart SOAR

- **Positioning:** "#1 independent SOAR platform"
- **Pricing:** Minimum ~$100,000/year
- **Key Innovation:** Event Pipeline for intelligent alert standardization, consolidation, enrichment, and false positive dismissal
- **MSSP Focus:** Full multi-tenancy, hyperscalability, 5-minute onboarding, codeless integrations
- **Performance:** 90% decrease in MTTD and MTTR for clients
- **Significance:** Strong MSSP/MDR play; demonstrates independent SOAR viability

---

## 3. Market Gaps & Whitespace

### 3.1 What SOC Analysts Hate About Current SOAR Tools

Based on the SANS 2025 SOC Survey, Gartner research, and practitioner feedback:

1. **Complexity & Setup Time:** Enterprise SOAR platforms take weeks-to-months to deploy. Playbook creation requires specialized skills. Most SOCs lack the engineering staff to maintain SOAR infrastructure.

2. **Cost Barrier:** XSOAR at ~$250K/year, D3 at ~$100K/year minimum. Even "affordable" platforms require significant integration engineering costs on top of license fees. SMBs are effectively priced out of enterprise SOAR.

3. **Maintenance Burden:** SOAR playbooks break when tools update APIs. Integration maintenance is ongoing. Playbook logic must be updated as threats evolve. CISA's May 2025 guidance explicitly warns: "Neither a SIEM nor a SOAR is a 'set and forget' tool."

4. **Playbook Rigidity:** Legacy SOAR treats every alert like a "five-alarm fire," flooding analysts with noise and contextless data. Static playbooks cannot adapt to novel threats or correlate evidence dynamically.

5. **False Promise of Automation:** 42% of SOCs dump all data into SIEM without a retrieval plan (SANS 2025). 85% of SOCs are still primarily reactive (triggered by endpoint alerts, not proactive detection). The tools automate steps but not judgment.

### 3.2 Human-in-the-Loop Shortfalls

**Current State:**
- Well-designed playbooks include conditional logic that pauses for analyst approval on high-impact actions (host quarantine, user notification, etc.)
- Most HITL implementations are binary: "approve/deny" checkpoints
- Confidence-based routing exists in concept (pause if AI confidence < threshold) but is rarely implemented well

**Gaps:**
- **No graduated autonomy:** Systems are either fully automated or fully manual. No "AI handles low-risk decisions, escalates medium-risk, always escalates high-risk" continuum.
- **No learning from decisions:** When analysts override AI recommendations, that feedback is rarely fed back to improve future automation.
- **No explanation layer:** When AI makes a decision, analysts get a verdict but rarely understand the reasoning chain.
- **No regulatory-compliant audit trail:** FINRA's 2026 Oversight Report warns that AI-driven workflow engines performing sequences of actions must maintain "full chain of activity" reconstructability.

### 3.3 AI-Powered Runbook Generation vs. Execution

| Capability | Current State (2025-2026) |
|-----------|--------------------------|
| **AI Runbook Generation** | Active area. Rootly converts "tribal knowledge" from Slack conversations into codified AI runbooks via RAG. Splunk SOAR has AI Playbook Authoring (natural language to playbook). Google SecOps uses Gemini for AI runbook generation via MCP. HCL BigFix Runbook AI generates runbooks from operational data. |
| **AI Runbook Execution** | More nascent. Torq's Socrates executes via multi-agent system. CrowdStrike Charlotte orchestrates agent execution. Google SecOps executes runbooks for threat hunting via MCP. Most implementations still require human approval for execution. |
| **Gap** | No platform does BOTH generation AND adaptive execution well. Generation tools produce static outputs. Execution tools require pre-authored playbooks. The "living runbook" that generates, executes, adapts, and improves itself does not exist. |

### 3.4 Confidence-Based Automation

**Who's doing it:**
- CrowdStrike Charlotte SOAR mentions "confidence" but details are sparse
- IBM QRadar SOAR uses "dynamic playbooks" with conditional logic
- Torq Socrates claims autonomous resolution of 95% Tier-1 alerts
- Generic HITL patterns include "confidence-based routing" where agents defer to humans below a threshold

**How well:**
- Mostly marketing claims. No standardized confidence scoring framework exists across the industry.
- No platform publishes accuracy/precision metrics for their confidence assessments.
- The concept of "graduated autonomy based on confidence" is discussed but not productized.

### 3.5 SOAR for Small/Medium Teams

**Market Reality:**
- SMEs hold 51.6% of the SOAR market share (2025) and post the highest growth rate (19.6% CAGR through 2030)
- Yet large enterprises retained 78% of revenue share in 2024
- This means: many small teams are adopting SOAR but spending very little, likely on free/low-cost tools

**Current Options for Small Teams:**
| Tool | Cost | Limitation |
|------|------|-----------|
| Shuffle (OSS) | Free | Performance constraints; no native AI; limited docs |
| Tines Community | Free | 3 Stories limit |
| Tracecat (OSS) | Free | Early stage; small community |
| TheHive Community | Free | Read-only after 14-day trial; no longer fully open source |
| Microsoft Sentinel | Pay-per-use | Requires Azure; SOAR is basic |
| CISA Logging Made Easy | Free | Log management only, not SOAR |

**The Gap:** No solution provides AI-powered runbook automation that is free/cheap, easy to set up, and designed specifically for 1-5 person security teams. This is the whitespace RunbookPilot should target.

---

## 4. SOC Analyst Workflow Research

### 4.1 Typical Alert Triage Workflow (2025)

Based on current industry practices and the Dropzone AI/VMRay 5-step triage framework:

```
Alert Fired (SIEM/EDR/XDR)
    |
    v
[1] SMART ALERT GROUPING
    - Cluster related signals by time, systems, techniques
    - Determine: coordinated activity or isolated event?
    |
    v
[2] INSTANT CONTEXT GATHERING
    - System criticality lookup
    - User behavior baseline check
    - Recent change review
    - Known threat campaign matching
    |
    v
[3] ENRICHMENT
    - Threat intelligence feeds (VirusTotal, AbuseIPDB, etc.)
    - MITRE ATT&CK mapping
    - Historical analysis data
    - Affected asset inventory
    |
    v
[4] INVESTIGATION & VALIDATION
    - True Positive / False Positive determination
    - Root cause analysis
    - Scope assessment (lateral movement? data exfil?)
    |
    v
[5] RESPONSE / ESCALATION
    - Match to response playbook by threat type + severity
    - Execute containment (or escalate to Tier 2/3)
    - Document findings + update case
    |
    v
[6] POST-INCIDENT
    - Update runbook with new insights
    - Feed back to detection rules
    - Metrics: MTTD, MTTR, false positive rate
```

**Key Performance Benchmark:** Leading implementations achieve 3-10 minute investigations with 90% alert coverage using AI + automation (Dropzone AI data).

### 4.2 Pain Points

| Pain Point | SANS 2025 Data / Industry Evidence |
|-----------|-----------------------------------|
| **Alert Fatigue** | 64% cite high false positive rates from vendor tools. >70% of SOC analysts report burnout. Analysts face thousands of daily notifications. |
| **Context Switching** | Splunk ES 8.2 specifically addresses "analysts switching between fragmented tools" -- meaning this was a known, severe problem. |
| **Tribal Knowledge Loss** | Average SOC analyst tenure: 3-5 years (SANS 2025). 62% say their org isn't doing enough to retain staff. Knowledge walks out the door. |
| **Runbook Staleness** | Modern systems change 10-100 times/day. Runbooks don't auto-update. Without maintenance, they "drift from reality until they're dangerously misleading." Stack Overflow (Oct 2025): "Your runbooks are obsolete in the age of agents." |
| **Reactive Operations** | 85% of SOCs primarily trigger response from endpoint alerts, not proactive detection. Even "threat hunting" is often retroactive analysis, not hypothesis-driven investigation. |

### 4.3 How Analysts Actually Use Runbooks Today

Based on Tufin, Rootly, incident.io, and practitioner sources:

1. **Wiki Pages / Confluence:** Most common. Static documentation that goes stale. New analysts must read and interpret. No execution linkage.

2. **SOAR Playbooks:** Organizations with enterprise SOAR encode some procedures as automated playbooks. But playbook coverage is typically <30% of alert types.

3. **Mental Checklists:** Senior analysts carry procedures in their heads. This IS the tribal knowledge problem. When they leave, the knowledge leaves.

4. **Ticketing System Templates:** JIRA/ServiceNow templates with checklist fields. Better than nothing but no automation linkage.

5. **Chat Threads:** Teams/Slack threads where analysts ask "how do we handle X?" and get answers from senior staff. Rootly specifically targets converting these into AI runbooks.

**The reality:** Runbooks serve as training materials for onboarding but degrade into shelf-ware within months. The most useful "runbook" in most SOCs is the senior analyst's brain.

### 4.4 Analyst Decisions That Could Be AI-Assisted

Based on IBM, Rapid7, Radiant Security, and Splunk research:

| Decision Point | Current Process | AI Assist Opportunity |
|---------------|----------------|----------------------|
| **True/False Positive?** | Manual correlation across 3-5 tools | AI correlates all data, presents verdict + confidence |
| **Severity Classification** | Analyst judgment based on experience | AI scores risk with business context (blast radius, data sensitivity, regulatory impact) |
| **Scope Assessment** | Manual lateral movement investigation | AI maps affected systems, identifies potential spread |
| **Response Selection** | Choose from playbook menu (or memory) | AI recommends response based on similar past incidents |
| **Escalation Decision** | Gut feeling + severity thresholds | AI evaluates analyst skill match, workload, incident complexity |
| **Communication Drafting** | Manual writing of stakeholder updates | AI generates incident summaries, executive briefings |
| **Post-Incident Learning** | Manual runbook updates (rarely done) | AI captures new procedures, suggests runbook updates |

---

## 5. Technology Trends (2025-2026)

### 5.1 LLM Integration in Security Operations

**Who's Doing It:**
| Vendor | LLM Approach |
|--------|-------------|
| CrowdStrike | Charlotte AI (proprietary); AgentiX with multi-agent architecture |
| Palo Alto | Cortex AgentiX (proprietary, trained on 1.2B executions) |
| Torq | Socrates multi-agent system with RAG (acquired Revrod) |
| Google | Gemini integration in SecOps; MCP-based AI runbooks |
| Microsoft | Copilot for Security; LLM-powered Sentinel queries |
| Splunk/Cisco | AI Playbook Authoring; agentic AI solutions (Oct 2025) |
| Dropzone AI | LLM-based autonomous investigation (not rule-based) |
| BlinkOps | Natural language to automation; micro-agent builder |

**What Works:**
- Log summarization and report generation
- Alert triage assistance (presenting enriched context)
- Natural language to playbook/query translation
- Short, focused interactions (interpreting telemetry, refining communication)
- Analysts use LLMs as "on-demand aids for sensemaking and context-building" rather than high-stakes decision-making (academic research, arxiv 2508.18947)

**What Doesn't Work:**
- Fully autonomous decision-making on novel threats (trust/governance gap)
- Adversarial robustness (models can be poisoned or evaded)
- Integration with legacy systems (API incompatibilities)
- Hallucination in security context (fabricated IOCs, incorrect correlations)
- Shadow AI (47% of users bypass controls via personal accounts)
- MCP is "being adopted faster than it's being secured" -- tools not designed for agentic use

**Key Statistic:** 46% of organizations plan to start using AI agents in security operations in 2026 (Gartner 2025 Cybersecurity Innovations survey).

### 5.2 Autonomous vs. Semi-Autonomous Response

**Industry Sentiment:**
- Torq claims 95% Tier-1 autonomous resolution
- CrowdStrike and Palo Alto positioning toward "Autonomous SOC"
- But: "Adoption will lag maturity -- not because the technology isn't ready, but because trust, governance and skills are not"
- In 2026, "AI agent governance becomes its own security problem -- and its own product category"

**Regulatory Concerns:**
- **FINRA 2026 Oversight Report:** AI-driven workflow engines selecting intermediate actions (querying systems, pulling data, triggering downstream) must be treated with "the same controls applicable to any associated person performing a comparable function." Full chain-of-activity reconstructability required.
- **CISA May 2025 Guidance:** "Ensuring that the SOAR only takes appropriate action in response to actual cyber security incidents, and does not take action against regular network activity or impede human incident responders" is a key challenge.
- **International AI Safety Report 2026:** AI agents "pose heightened risks because they act autonomously, making it harder for humans to intervene before failures cause harm."

**Consensus:** Semi-autonomous with human-in-the-loop is the practical path for 2026-2027. Full autonomy requires governance frameworks that don't yet exist.

### 5.3 Open-Source SOAR Momentum

| Project | Status (2025-2026) |
|---------|-------------------|
| **Shuffle** | ~1.9K GitHub stars. Industry standard for open-source SOAR. Constrained by server capacity. Active development. |
| **TheHive** | 52 releases since 2016. Moved to freemium/private-source model. Community trust eroding due to licensing shift. |
| **Tracecat** | Y Combinator W24. Growing rapidly. AI-native, Docker-deployable. Most promising new entrant. |
| **StackStorm** | General automation (not security-specific). Under 20K stars. |
| **Wazuh** | SIEM/XDR not SOAR, but commonly paired with Shuffle/TheHive for complete stack. |

**Trend:** Open-source SOAR is growing in adoption but no project has achieved dominant community scale. TheHive's licensing shift and Shuffle's performance issues create opportunity for a well-positioned new entrant.

### 5.4 Gartner Retired the SOAR Magic Quadrant

**Critical Market Signal:** Gartner has officially retired its Magic Quadrant for SOAR, publishing only a Market Guide. Their rationale:

- SOAR as standalone technology has been "surpassed"
- Components have been "subsumed by other products and services"
- Automation is "increasingly an expected feature" rather than a separate category
- Future driven by "generative AI-based solutions rather than traditional SOAR platforms"

**Implication for RunbookPilot:** Don't position as "another SOAR." Position as an AI-powered runbook automation tool that fills the gap between SOAR's death and the agentic AI future's arrival.

---

## 6. Portfolio Differentiation Strategy

### 6.1 What Hiring Managers Want (by Organization Type)

#### Enterprise SOCs (Fortune 500)
- **What impresses:** Deep integration knowledge (Splunk, CrowdStrike, Microsoft stack); ability to design and deploy SOAR at enterprise scale; MITRE ATT&CK fluency; understanding of regulatory compliance in automation.
- **RunbookPilot angle:** Demonstrate you understand the gap between "we bought XSOAR" and "our analysts actually use automation effectively." Show you can think about playbook coverage, graduated autonomy, and audit trails.
- **Key skills to showcase:** Python scripting, API integration design, playbook architecture, metrics-driven SOC operations.

#### MSSPs / MDR Providers
- **What impresses:** Multi-tenancy architecture; understanding of SLA-driven automation; ability to scale security operations across diverse customer environments; cost efficiency thinking.
- **RunbookPilot angle:** Build multi-tenant support natively. Show understanding of how MSSPs need standardized-but-customizable runbooks across clients. Demonstrate MSSP pricing model awareness.
- **Key skills to showcase:** Multi-tenant architecture, API design, workflow templating, operational metrics.

#### Cloud-Native Security Teams
- **What impresses:** Infrastructure-as-code mentality; container/Kubernetes security; CI/CD pipeline integration; API-first architecture; open-source contributions.
- **RunbookPilot angle:** Docker-deployable, API-first, integrates with cloud-native tooling (AWS Security Hub, GCP Security Command Center, Azure Sentinel). YAML-based configuration.
- **Key skills to showcase:** Docker/K8s, IaC, REST API design, cloud security architecture.

#### Startups Building Security Products
- **What impresses:** Full-stack thinking; ability to ship fast; understanding of product-market fit; open-source community building; AI/ML integration skills.
- **RunbookPilot angle:** This IS a product. The fact that you built it demonstrates you can ship. Focus on: clean architecture, good documentation, test coverage, CI/CD pipeline.
- **Key skills to showcase:** TypeScript/Python, LLM integration, product thinking, system design.

### 6.2 What Makes RunbookPilot Stand Out

Based on the competitive analysis, the following attributes would maximize differentiation:

1. **Open Source + AI-Native:** Only Tracecat occupies this space today. Shuffle is OSS but not AI-native. Enterprise tools are AI-native but not open source. Being BOTH is a clear differentiator.

2. **Confidence-Based Graduated Autonomy:** No platform has productized this well. A system that automatically determines: "I'm 95% confident this is a false positive, auto-closing" vs. "I'm 70% confident, here's my reasoning -- analyst please confirm" vs. "I'm 30% confident, escalating with full context" would be genuinely novel.

3. **Living Runbooks:** Runbooks that self-update based on incident outcomes, analyst feedback, and environmental changes. This solves the "runbook staleness" problem that plagues every SOC.

4. **DetectForge Integration:** A detection-to-response pipeline where DetectForge generates Sigma/YARA/Suricata rules and RunbookPilot automatically generates corresponding response runbooks is a unique end-to-end capability no commercial or open-source tool offers.

5. **Designed for Small Teams:** Enterprise SOAR starts at $100K-$250K/year. Small teams need AI-powered automation that's free, deploys in minutes, and doesn't require a SOAR engineer to maintain.

---

## 7. Competitive Positioning Matrix

### 7.1 Feature Comparison

| Feature | XSOAR | Splunk SOAR | Tines | Torq | Shuffle | TheHive | Tracecat | **RunbookPilot (Proposed)** |
|---------|-------|-------------|-------|------|---------|---------|----------|---------------------------|
| Free/OSS Tier | Trial only | No | 3 Stories | No | Yes | Freemium | Yes | **Yes (fully OSS)** |
| AI-Native | AgentiX | AI Playbooks | Basic | Socrates MAS | No | No | Basic | **Core design** |
| Confidence Scoring | Partial | No | No | Claims 95% | No | No | No | **Graduated autonomy** |
| Runbook Generation | Via AgentiX | NL to playbook | No | Runbook Agent | No | No | AI-assisted | **AI + template** |
| Runbook Execution | Full | Full | Full | Full | Full | Limited | Basic | **Confidence-gated** |
| Runbook Self-Update | No | No | No | Partial | No | No | No | **Core design** |
| HITL Approve/Deny | Yes | Yes | Yes | Yes | Basic | Basic | Basic | **Graduated** |
| Small Team Friendly | No ($250K) | No | Partial (3 free) | No | Yes | Partial | Yes | **Primary target** |
| Multi-Tenant | Yes | Yes | Enterprise | Yes | No | Enterprise | No | **Planned** |
| Detection Integration | No | No | No | No | No | Cortex only | No | **DetectForge pipeline** |

### 7.2 Market Position Map

```
                    AI-Native / Intelligent
                           ^
                           |
         Torq HyperSOC  *  |  * CrowdStrike Charlotte
                           |
     Dropzone AI *         |         * Palo Alto AgentiX
                           |
    BlinkOps *             |           * Google SecOps
                           |
  ----RunbookPilot*--------+-------------------------------->
     (proposed)            |                    Enterprise Scale
  Small Team /             |
  Accessible               |
                           |
     Tracecat *            |         * Splunk SOAR
                           |
     Shuffle *             |    * IBM QRadar SOAR
                           |
     TheHive *             |  * FortiSOAR     * D3 Smart SOAR
                           |
                    Traditional / Playbook-Based
```

**RunbookPilot Target Quadrant:** Lower-left -- accessible AND AI-native. This is the least contested quadrant.

---

## 8. Strategic Recommendations for RunbookPilot

### 8.1 Core Value Proposition

> "AI-guided runbook automation for security teams who can't afford enterprise SOAR but need more than static wiki pages. Open source. Confidence-based. Human-in-the-loop by design."

### 8.2 Must-Have Features (Differentiation Tier)

1. **Confidence-Gated Automation Engine**
   - Every AI decision includes a confidence score
   - Configurable thresholds: auto-execute (>90%), suggest-and-wait (50-90%), escalate-with-context (<50%)
   - Analyst feedback loops that improve confidence calibration over time

2. **Living Runbooks**
   - Runbooks stored as structured data (not wiki markdown)
   - Auto-update suggestions after each incident execution
   - Drift detection: flag when environment changes make runbook steps invalid
   - Version history with diff view

3. **DetectForge Pipeline Integration**
   - When DetectForge generates a new Sigma rule, RunbookPilot auto-generates a matching response runbook
   - Maps detection logic to response steps via MITRE ATT&CK techniques
   - Creates the first end-to-end open-source detection-to-response pipeline

4. **AI Investigation Assistant**
   - LLM-powered enrichment and context gathering
   - Natural language incident summaries
   - Suggested next steps based on similar past incidents
   - Full reasoning chain visible to analyst (explainable AI)

5. **Audit Trail with Regulatory Compliance**
   - Full chain-of-activity logging (aligned with FINRA/CISA guidance)
   - Every AI decision, analyst override, and execution step recorded
   - Exportable compliance reports

### 8.3 Architecture Recommendations

- **Runtime:** Bun + TypeScript (consistent with DetectForge)
- **API-First:** REST + potentially MCP support for agentic AI integration
- **Deployment:** Docker single-container for small teams; Docker Compose for production
- **LLM Integration:** OpenRouter (consistent with DetectForge) for model-agnostic AI
- **Data Format:** YAML-based runbook definitions (industry convention)
- **Integrations:** Start with common free/OSS tools: Wazuh, TheHive, Shuffle, Elastic

### 8.4 Market Timing

**Why Now (2026) is Optimal:**
- Gartner killed the SOAR Magic Quadrant -- the category is in transition
- 46% of orgs plan to start AI agents in SecOps in 2026 (Gartner)
- SMEs are the fastest-growing SOAR segment (19.6% CAGR) but underserved
- Enterprise tools are racing to $1B+ (XSIAM, Torq at $1.2B valuation) -- leaving the small team market behind
- Open-source AI-native SOAR has exactly one competitor (Tracecat) which is early-stage
- CISA/FINRA regulatory guidance creates demand for auditable, human-in-the-loop systems

---

## 9. Sources

### SOAR Platform Sources
- [Palo Alto XSOAR Pricing Guide 2026 - UnderDefense](https://underdefense.com/industry-pricings/palo-alto-networks-pricing-ultimate-guide-for-security-products/)
- [Palo Alto XSOAR Pricing - TrustRadius](https://www.trustradius.com/products/palo-alto-networks-cortex-xsoar/pricing)
- [Palo Alto XSOAR Reviews - PeerSpot](https://www.peerspot.com/products/palo-alto-networks-cortex-xsoar-reviews)
- [Cortex XSOAR Product Page - Palo Alto Networks](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
- [XSOAR Reviews 2026 - Gartner Peer Insights](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/palo-alto-networks/product/cortex-xsoar)
- [2025: The Year of the Autonomous SOC - Palo Alto Networks Blog](https://www.paloaltonetworks.com/blog/security-operations/2025-the-year-of-the-autonomous-soc-the-year-of-xsiam/)
- [Palo Alto Launches Cortex AgentiX - Stock Titan](https://www.stocktitan.net/news/PANW/palo-alto-networks-unveils-cortex-agenti-x-to-build-deploy-and-79ao1yn0xcov.html)
- [Splunk AI Roadmap Under Cisco - TechTarget](https://www.techtarget.com/searchitoperations/news/366630519/Under-Cisco-Splunk-AI-roadmap-tees-up-pricing-overhaul)
- [Splunk SOAR Reviews 2026 - Gartner Peer Insights](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/cisco-systems-splunk/product/splunk-soar)
- [Splunk .conf25: Cisco, AI, and Data - Forrester](https://www.forrester.com/blogs/splunk-conf25-cisco-ai-and-data/)
- [Cisco Agentic AI-Powered SOC Solutions - techENT](https://techent.tv/2025/10/07/cisco-introduces-agentic-ai-powered-solutions-powered-by-splunk-into-its-security-operations-center/)
- [Tines Reviews 2026 - Gartner Peer Insights](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/tines/product/tines)
- [Tines SOAR Comparison Page](https://www.tines.com/soar/)
- [Tines Pricing Model](https://www.tines.com/pricing/)
- [Tines Community Edition Announcement](https://www.tines.com/blog/announcing-the-tines-community-edition/)
- [Swimlane Turbine Reviews 2026 - Gartner](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/swimlane/product/swimlane-turbine)
- [Torq Hyperautomation Reviews 2026 - Gartner](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/torq/product/torq-hyperautomation)
- [Torq $140M Series D at $1.2B Valuation](https://torq.io/news/torq-seriesd/)
- [Torq HyperSOC Platform](https://torq.io/hypersoc/)
- [Torq Socrates AI SOC Analyst](https://torq.io/socrates/)
- [Torq Multi-Agent System for SOC](https://torq.io/ai-agents-for-the-soc/)
- [Shuffle SOAR - Official Site](https://shuffler.io/)
- [Shuffle GitHub Repository](https://github.com/Shuffle/Shuffle)
- [TheHive - StrangeBee](https://strangebee.com/thehive/)
- [TheHive 5 License Documentation](https://docs.strangebee.com/thehive/installation/licenses/about-licenses/)
- [TheHive Pricing (On-Prem)](https://strangebee.com/thehive-pricing-on-prem/)
- [Cortex - StrangeBee](https://strangebee.com/cortex/)
- [Google Security Operations](https://cloud.google.com/security/products/security-operations)
- [Chronicle SOAR - Google Cloud](https://cloud.google.com/chronicle-soar)
- [IBM QRadar SOAR Product Page](https://www.ibm.com/products/qradar-soar)
- [IBM QRadar SOAR Pricing](https://www.ibm.com/products/qradar-soar/pricing)
- [IBM QRadar SOAR Features](https://www.ibm.com/products/qradar-soar/features)
- [Microsoft Sentinel Playbooks - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/automation/automate-responses-with-playbooks)
- [Azure Logic Apps for Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/automation/logic-apps-playbooks)
- [Microsoft Sentinel Pricing](https://www.microsoft.com/en-us/security/pricing/microsoft-sentinel)
- [Microsoft Sentinel Pricing 2025 - UnderDefense](https://underdefense.com/industry-pricings/microsoft-sentinel-pricing/)
- [Fortinet FortiSOAR Product Page](https://www.fortinet.com/products/fortisoar)
- [FortiSOAR Reviews 2026 - Gartner](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/fortinet/product/fortisoar)

### Emerging AI-Native Players
- [CrowdStrike Charlotte Agentic SOAR Announcement](https://www.crowdstrike.com/en-us/blog/crowdstrike-leads-new-evolution-of-security-automation-with-charlotte-agentic-soar/)
- [CrowdStrike Seven New Agents](https://www.crowdstrike.com/en-us/blog/crowdstrike-delivers-seven-agents-to-build-agentic-security-workforce/)
- [Charlotte AI AgentiX Product Page](https://www.crowdstrike.com/en-us/solutions/charlotte-agentic-soar/)
- [Dropzone AI Product Page](https://www.dropzone.ai/)
- [Dropzone AI $37M Series B](https://www.dropzone.ai/press-release/dropzone-ai-37m-series-b-funding-ai-soc-agents)
- [Dropzone AI 11x ARR Growth](https://www.businesswire.com/news/home/20260115943406/en/Dropzone-AI-Closes-2025-with-11x-ARR-Growth-Fortune-Cyber-60-Recognition-and-37m-Series-B)
- [Radiant Security Platform](https://radiantsecurity.ai/)
- [Radiant Security Adaptive AI SOC](https://radiantsecurity.ai/blog/introducing-broadest-soc-coverage-with-adaptive-ai-agents/)
- [BlinkOps Platform](https://www.blinkops.com/)
- [BlinkOps $50M Raise - SiliconANGLE](https://siliconangle.com/2025/07/28/blinkops-raises-50m-expand-deployment-no-code-security-micro-agents/)
- [BlinkOps No-Code Agent Builder - SiliconANGLE](https://siliconangle.com/2025/04/22/blinkops-launches-no-code-custom-cybersecurity-ai-agent-builder/)
- [Tracecat Official Site](https://www.tracecat.com/)
- [Tracecat GitHub Repository](https://github.com/TracecatHQ/tracecat)
- [Tracecat OSS SOAR - Help Net Security](https://www.helpnetsecurity.com/2024/04/30/tracecat-open-source-automation-platform-soar/)
- [D3 Security Smart SOAR Platform](https://d3security.com/platform/soar-platform-overview/)
- [D3 Security Smart SOAR Reviews 2026 - Gartner](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions/vendor/d3-security/product/smart-soar)

### Market Research & Analysis
- [SOAR Market Size and 2030 Growth - Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/security-orchestration-automation-and-response-market)
- [SOAR Market Analysis Report 2035 - Future Market Insights](https://www.futuremarketinsights.com/reports/security-orchestration-automation-and-response-soar-market)
- [Gartner SOAR Magic Quadrant Discontinued - Security Boulevard](https://securityboulevard.com/2025/04/wheres-the-soar-magic-quadrant/)
- [Saying Goodbye to SOAR - BlinkOps](https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations)
- [SOAR Is Dead, Long Live SOAR - Dark Reading](https://www.darkreading.com/cybersecurity-operations/soar-is-dead-long-live-soar)
- [Gartner Says SOAR Is Obsolete - Torq](https://torq.io/blog/gartner-automated-incident-response/)
- [23 Best SOAR Platforms 2026 - CTO Club](https://thectoclub.com/tools/best-soar-platforms/)
- [Best SOAR Solutions 2026 - Gartner Peer Insights](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions)
- [Top 5 Open Source SOAR Tools - AIMultiple](https://aimultiple.com/open-source-soar)
- [Open Source SOAR Uncovered - CyberSec Automation](https://www.cybersec-automation.com/p/opensource-soar-uncovered)
- [Top 5 Open Source SOAR Solutions 2025 - Medium/UTMStack](https://medium.com/@marketing_38143/top-5-open-source-soar-solutions-in-2025-f7e931546dd0)

### SOC Workflow & Analyst Research
- [SANS 2025 SOC Survey](https://www.sans.org/white-papers/sans-2025-soc-survey)
- [SANS SOC Survey 2025 PDF - Elastic](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)
- [SANS SOC Survey Key Findings - Yahoo Finance](https://finance.yahoo.com/news/sans-2025-soc-survey-exposes-131400675.html)
- [SANS SOC Survey: SOCs in Slow Motion - Torq](https://torq.io/blog/sans-2025-soc-survey/)
- [SANS SOC Survey Insights - Swimlane](https://swimlane.com/blog/global-soc-survey-insights/)
- [SANS SOC Survey Insights - Tines](https://www.tines.com/blog/sans-soc-survey-2025/)
- [Alert Fatigue Research - ACM Computing Surveys](https://dl.acm.org/doi/10.1145/3723158)
- [SOC Alert Fatigue - CyberDefenders](https://cyberdefenders.org/blog/soc-alert-fatigue/)
- [Alert Fatigue Prevention 2026 - Torq](https://torq.io/blog/cybersecurity-alert-management-2026/)
- [Alert Triage Guide 2025 - Dropzone AI](https://www.dropzone.ai/resource-guide/alert-triage-guide-2025)
- [Alert Triage Complete Guide - Dropzone AI](https://www.dropzone.ai/glossary/alert-triage-in-2025-the-complete-guide-to-90-faster-investigations)
- [Alert Triage Definition - VMRay](https://www.vmray.com/alert-triage/)
- [SOC Runbook Role - Tufin](https://www.tufin.com/blog/role-soc-runbook-streamlining-soc-operations)
- [How to Build Effective Runbooks - incident.io](https://incident.io/blog/how-to-build-effective-runbooks-for-your-soc)
- [Runbook Staleness in the Age of Agents - Stack Overflow](https://stackoverflow.blog/2025/10/24/your-runbooks-are-obsolete-in-the-age-of-agents/)
- [Rootly AI Runbooks](https://rootly.com/sre/rootly-ai-runbooks-elevate-sre-automation-workflows)
- [Rootly: Convert Tribal Knowledge to AI Runbooks](https://rootly.com/sre/convert-tribal-knowledge-to-ai-runbooks-with-rootly-in-2025)

### AI & Technology Trends
- [AI-Augmented SOC: LLMs and Agents Survey - MDPI](https://www.mdpi.com/2624-800X/5/4/95)
- [LLMs in the SOC: Empirical Study - arxiv 2508.18947](https://arxiv.org/abs/2508.18947)
- [LLMs for SOCs: Comprehensive Survey - arxiv 2509.10858](https://arxiv.org/abs/2509.10858)
- [Agentic AI and Cybersecurity Survey - arxiv 2601.05293](https://arxiv.org/html/2601.05293v1)
- [Security Predictions 2026 - Vectra AI](https://www.vectra.ai/blog/security-predictions-for-2026-when-ai-scales-the-offense-defense-must-evolve)
- [AI Security Trends 2026 - Practical DevSecOps](https://www.practical-devsecops.com/ai-security-trends-2026/)
- [2025 Wrapped: AI in Security Operations - Detection at Scale](https://www.detectionatscale.com/p/2025-wrapped-ai-security-operations-reading)
- [AI Runbooks for Google SecOps via MCP - Google Cloud Community](https://security.googlecloudcommunity.com/community-blog-42/ai-runbooks-for-google-secops-security-operations-with-model-context-protocol-3988)
- [AI for Runbook Automation 2025 - XenonStack](https://www.xenonstack.com/insights/ai-for-runbook-automation)

### Regulatory & Governance
- [FINRA 2026 Oversight Report on Autonomous AI - Snell & Wilmer](https://www.swlaw.com/publication/finras-2026-oversight-report-signals-a-supervisory-reckoning-for-autonomous-ai/)
- [International AI Safety Report 2026](https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026)
- [CISA SIEM and SOAR Implementation Guidance](https://www.cisa.gov/news-events/alerts/2025/05/27/new-guidance-siem-and-soar-implementation)
- [CISA SOAR Practitioner Guidance PDF - DoD](https://media.defense.gov/2025/May/27/2003722066/-1/-1/0/Implementing-SIEM-and-SOAR-platforms-Practitioner-guidance.PDF)
- [CISA SOAR Guidance Analysis - D3 Security](https://d3security.com/blog/cisa-soar-guidance-soc-automation/)

### Human-in-the-Loop
- [Human-in-the-Loop in Cybersecurity - Rapid7](https://www.rapid7.com/fundamentals/human-in-the-loop/)
- [Human-in-the-Loop in SOC Automation - XenonStack](https://www.xenonstack.com/blog/human-loop-soc-automation)
- [HITL in AI Workflows - Zapier](https://zapier.com/blog/human-in-the-loop/)
- [SOAR and Automation for SOC Analysts - CyberDefenders](https://cyberdefenders.org/blog/soar-and-automation-for-soc-analysts)
- [AI-Driven SOC Co-Pilots - IBM](https://www.ibm.com/think/insights/how-ai-driven-soc-co-pilots-will-change-security-center-operations)
- [AI Use Cases for the SOC - Splunk](https://www.splunk.com/en_us/blog/learn/ai-use-cases-soc.html)

### MSSP/MDR Market
- [MSSP Cybersecurity Trends 2026 - Torq](https://torq.io/blog/mssp-cybersecurity-trends-2026/)
- [MSSP SOAR Scaling - D3 Security](https://d3security.com/capabilities/software-to-scale-your-mssp/)
- [MSSPs AI Security Automation - Swimlane](https://swimlane.com/solutions/industries/mssps/)
- [What Happens to MSSPs in the AI-SOC Age - The Hacker News](https://thehackernews.com/expert-insights/2025/10/what-happens-to-mssps-and-mdrs-in-age.html)
- [Autonomous SecOps for MSSPs - MSSP Alert](https://www.msspalert.com/native/why-autonomous-secops-is-the-next-competitive-advantage-for-mssps-and-mdrs)

### Portfolio & Career
- [Portfolio Projects That Get You Hired - Cyber Security Jobs](https://cybersecurityjobs.tech/career-advice/portfolio-projects-that-get-you-hired-for-cyber-security-jobs-with-real-github-examples-)
- [Building a Cybersecurity Portfolio - Cyber Security District](https://www.cybersecuritydistrict.com/a-step-by-step-guide-to-building-a-cybersecurity-portfolio/)
- [Cyber Security Projects for Resume 2026 - StationX](https://www.stationx.net/cyber-security-projects-for-resume/)
- [SOAR Engineer Jobs - ZipRecruiter](https://www.ziprecruiter.com/Jobs/Soar-Engineer)
- [GitHub Projects for Cybersecurity Portfolio - Cyber Security District](https://www.cybersecuritydistrict.com/top-github-projects-to-showcase-in-a-cybersecurity-portfolio/)

---

*This report was compiled on February 10, 2026 using web research across 50+ sources spanning vendor documentation, analyst reports, academic research, practitioner surveys, and industry publications.*

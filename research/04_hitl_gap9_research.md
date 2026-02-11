# Human-in-the-Loop Optimization in Security Operations
## Comprehensive Research Report for RunbookPilot Architecture Planning

**Date:** 2026-02-10
**Purpose:** Deep research to inform RunbookPilot design -- an AI-guided SOC runbook automation tool with human-in-the-loop decision making
**Scope:** Academic research, vendor analysis, architecture patterns, metrics, and open problems

---

## Table of Contents

1. [The HITL Problem in Security Operations](#1-the-hitl-problem-in-security-operations)
2. [Confidence-Based Automation Models](#2-confidence-based-automation-models)
3. [Risk-Based Decision Frameworks](#3-risk-based-decision-frameworks)
4. [Measurable Outcomes](#4-measurable-outcomes)
5. [State of the Art (2025-2026)](#5-state-of-the-art-2025-2026)
6. [Architecture Patterns for HITL Systems](#6-architecture-patterns-for-hitl-systems)
7. [Implications for RunbookPilot](#7-implications-for-runbookpilot)

---

## 1. The HITL Problem in Security Operations

### 1.1 Why Fully Autonomous Security Response Fails

Fully autonomous security response systems face three fundamental failure modes:

**False Positive Catastrophe.** False positive rates in production SOC environments are devastating. A Devo SOC Performance Report found that **up to 53% of security alerts are false positives**, and 70% of SOCs struggle to manage alert volume. In extreme cases, false positive rates exceed 99% -- one monitored oil refinery's intrusion detection system generated nearly 27,000 alerts where only 76 were legitimate, a false positive rate of over 99.7%. An autonomous system acting on these would cause massive operational disruption.

Sources:
- [Why False Positives Are Still Killing Security Teams (OP Innovate)](https://op-c.net/blog/why-false-positives-killing-security-teams/)
- [99% False Positives: A Qualitative Study of SOC Analysts (USENIX Security)](https://www.usenix.org/system/files/sec22summer_alahmadi.pdf)
- [False Positive Rate in Security Alerts (KPI Depot)](https://kpidepot.com/kpi/false-positive-rate-security-alerts)

**Blast Radius Amplification.** In multi-cloud, sprawling infrastructure environments, even a single compromised credential can cascade into a full-blown breach. When automated systems take containment actions incorrectly -- isolating the wrong host, blocking legitimate traffic, or quarantining clean files -- the damage can exceed the original threat. If automated responses are inconsistent or disruptive, organizations lose faith in automation and hesitate to enable full autonomy.

Sources:
- [Blast Radius: What It Means in Cybersecurity (Lumos)](https://www.lumos.com/topic/blast-radius-in-cybersecurity)
- [Automated Vulnerability Remediation (SentinelOne)](https://www.sentinelone.com/cybersecurity-101/cybersecurity/what-is-automated-vulnerability-remediation/)

**Compliance and Liability Exposure.** Regulatory frameworks like SOC 2, HIPAA, and PCI-DSS require documented human oversight of security decisions. SOC 2 compliance **cannot be fully automated** -- organizations must demonstrate customized policies, controls, and governance with human approval. Understanding and managing blast radius is a core component of enterprise risk management and regulatory compliance. A fully autonomous system that takes an incorrect destructive action creates audit and liability problems that no compliance framework currently accounts for.

Sources:
- [SOC 2 Compliance Requirements (Secureframe)](https://secureframe.com/hub/soc-2/requirements)
- [SOC 2 Compliance: The Complete Introduction (AuditBoard)](https://auditboard.com/blog/soc-2-framework-guide-the-complete-introduction)

### 1.2 Why Pure Manual Response Fails

**Alert Fatigue and Volume.** Organizations face an average of **960 security alerts daily**, with enterprises over 20,000 employees seeing more than **3,000 alerts per day**. 77% of organizations have seen an increase in alert volume, with nearly half (46%) experiencing a spike of over 25% in the past year. Almost **90% of SOCs are overwhelmed by backlogs and false positives**, and 80% of analysts report feeling consistently behind.

Sources:
- [Alert Fatigue: What It Is & How to Fix It (Dropzone AI)](https://www.dropzone.ai/glossary/alert-fatigue-in-cybersecurity-definition-causes-modern-solutions-5tz9b)
- [The Cybersecurity Alert Fatigue Epidemic (DataBahn)](https://www.databahn.ai/blog/siem-alert-fatigue-false-positive)

**Analyst Burnout and Retention Crisis.** **71% of SOC analysts report burnout**, citing alert fatigue as the primary driver. **70% of SOC analysts with five years or less experience leave within three years** (SANS 2025 Survey). More than half of cybersecurity professionals cite workload as the primary source of stress, two-thirds reported experiencing burnout, and over 60% stated it contributed to staff turnover. The global cybersecurity workforce gap stands at **4-5 million professionals**.

Sources:
- [Alert Fatigue in Cybersecurity: Overcoming Analyst Burnout (Torq)](https://torq.io/blog/cybersecurity-alert-fatigue/)
- [SOC Analyst Burnout: How AI Is Changing the Game (Abnormal AI)](https://abnormal.ai/blog/soc-analyst-burnout-ai)
- [SANS 2025 SOC Survey (SANS Institute)](https://www.sans.org/white-papers/sans-2025-soc-survey)

**Mean Time to Respond (MTTR) Degradation.** Alert fatigue directly increases MTTD and MTTR. Low-value tickets crowd out meaningful work, causing critical alerts to be misclassified or missed entirely. The 2023 cross-industry MTTR average was approximately **72 hours** -- far too slow for modern threat actors who can move from initial access to lateral movement in minutes.

Sources:
- [MTTD & MTTR KPI: Essential Metrics for a Modern SOC (World Informatix)](https://worldinformatixcs.com/2025/12/04/mttd-mttr-kpi/)
- [How SOAR Helps Improve MTTD and MTTR Metrics (TechTarget)](https://www.techtarget.com/searchsecurity/feature/How-SOAR-helps-improve-MTTD-and-MTTR-metrics)

### 1.3 Academic Research on Optimal Human-AI Teaming

**The Unified Framework for SOC Collaboration (Mohsin et al., 2025).** The most directly relevant academic work is "A Unified Framework for Human-AI Collaboration in Security Operations Centers with Trusted Autonomy" (arXiv:2505.23397). This paper proposes a five-level autonomy framework mapped to HITL roles and task-specific trust thresholds:

| Level | Autonomy | Human Role | Description |
|-------|----------|------------|-------------|
| 0 | Manual | Full control | Human performs all tasks; AI provides no assistance |
| 1 | AI-Assisted | Human-in-the-Loop (HITL) | AI provides recommendations; human makes all decisions |
| 2 | Semi-Autonomous | Human-in-the-Loop (HITL) | AI acts with human approval required for key decisions |
| 3 | Supervised Autonomous | Human-on-the-Loop (HOtL) | AI acts independently; human monitors and can override |
| 4 | Fully Autonomous | Human-out-of-the-Loop (HOoTL) | AI operates independently within defined parameters |

The framework's key insight: as trust in AI systems grows, autonomy can be scaled incrementally, ensuring governance, accountability, and operational safety remain intact.

Source: [A Unified Framework for Human-AI Collaboration in SOCs (arXiv)](https://arxiv.org/abs/2505.23397)

**The A2C Framework for Alert Fatigue (Tariq et al., 2025).** Published in ACM Computing Surveys (Vol. 57, Issue 9), this comprehensive review examines alert fatigue through the **A2C lens: Automation, Augmentation, and Collaboration**. It identifies four major causes of alert fatigue and proposes research directions leveraging AI. The framework positions solutions along a spectrum from full automation to full human control, arguing that the optimal point varies by task type, risk level, and organizational maturity.

Source: [Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities (ACM)](https://dl.acm.org/doi/10.1145/3723158)

**Human-AI Teaming with Alert Prioritization (arXiv, 2025).** The paper "Towards Human-AI Teaming to Mitigate Alert Fatigue in Security Operations Centres" explores seamless transitions between automated AI validation, expert validation, and collaborative validation. The key finding: the human-AI team can **optimally balance decision-making responsibilities** by dynamically shifting between these modes, reducing cognitive load on analysts.

Source: [Towards Human-AI Teaming to Mitigate Alert Fatigue (ACM TOIT)](https://dl.acm.org/doi/10.1145/3670009)

**Flexible Autonomy Research.** Research on human-autonomy teaming emphasizes that **flexible autonomy** empowers both humans and AI to dynamically adjust control and decision authority based on context, situation, and operational requirements. The degree of autonomy should vary based on task complexity, system capabilities, and operational context. Within the literature, it is generally accepted that the human should be in charge of the team for both ethical and practical reasons -- humans are legally and morally responsible for actions and function more effectively when engagement is high.

Sources:
- [AI-Driven Human-Autonomy Teaming in Tactical Operations (arXiv)](https://arxiv.org/html/2411.09788v1)
- [Augmented Intelligence Framework for Human-AI Teaming (Springer)](https://link.springer.com/article/10.1007/s44230-025-00103-8)

### 1.4 Confidence Calibration

Confidence calibration addresses the critical question: **how does the system know when it's "sure enough" to act?**

**Confidence Threshold Calibration** involves systematically adjusting the decision boundary at which a model's predictions trigger specific actions. The most effective systems define tiered thresholds that align model certainty with risk and regulatory posture, routing uncertain outputs to human reviewers while speeding up high-confidence tasks.

**Reinforcement Learning for Calibration.** The most advanced implementations use reinforcement learning to automate calibration, treating it as an ongoing learning problem where the system receives feedback (in the form of alert dispositions) and adjusts settings to maximize reward functions like precision or F1 scores.

**Context-Aware Calibration.** Machine learning enables threshold adjustments that account for situational factors such as time of day, user role, asset sensitivity, and current threat landscape. When threat intelligence indicates active exploitation of a particular vulnerability, calibration systems can temporarily lower thresholds for related detection rules.

Sources:
- [Confidence Threshold Calibration (Conifers AI)](https://www.conifers.ai/glossary/confidence-threshold-calibration)
- [Using Confidence Scoring to Reduce Risk in AI-Driven Decisions (Multimodal)](https://www.multimodal.dev/post/using-confidence-scoring-to-reduce-risk-in-ai-driven-decisions)
- [Confidence Scoring in Threat Intelligence (Cyware)](https://www.cyware.com/resources/security-guides/cyber-threat-intelligence/what-is-confidence-scoring-in-threat-intelligence)

---

## 2. Confidence-Based Automation Models

### 2.1 Confidence Scoring Approaches

Confidence scores in security automation are probabilistic outputs indicating the degree of certainty about predictions, typically ranging from 0 to 1 (or 0%-100%). The primary approaches include:

**ML Model Probability Outputs.** Direct probability estimates from classification models (e.g., random forest, neural network) that assign threat likelihood scores. These suffer from calibration drift over time as threat landscapes change.

**Ensemble Confidence.** Multiple models vote on classification; confidence derives from agreement level. Higher agreement = higher confidence. This is more robust than single-model scoring but computationally expensive.

**Evidence-Based Scoring.** Aggregation of multiple indicator scores (IOC reputation, behavioral anomaly scores, contextual risk) into a composite confidence value. Used by threat intelligence platforms and SIEM correlation engines.

**LLM Reasoning Chains.** Newer approaches use large language models to generate reasoning chains about alert severity, producing both a classification and a natural-language justification. Prophet Security and Dropzone AI use this approach for autonomous triage.

### 2.2 Tiered Automation Implementation (Vendor Analysis)

**CrowdStrike Charlotte Agentic SOAR** (Announced November 2025)
- Bridges deterministic automation with adaptive intelligent agents
- Confidence thresholds drive workflow routing: high-confidence alerts trigger autonomous response; lower-confidence alerts queue for human review
- Multi-agent architecture: specialized AI agents ("droids") trained for particular tasks, with Charlotte AI coordinating
- Natural language and drag-and-drop controls for defining guardrails and missions
- Claims to reduce MTTR and ensure analysts receive only high-fidelity detections
- Can run autonomously, triaging thousands of alerts and triggering responses when confidence is high

Source: [CrowdStrike Charlotte Agentic SOAR](https://www.crowdstrike.com/en-us/blog/crowdstrike-leads-new-evolution-of-security-automation-with-charlotte-agentic-soar/)

**SentinelOne Purple AI + Singularity**
- Three automation tiers: Manual (ticket/escalate/human containment), Semi-automated (analyst approves suggested actions), Autonomous (automated containment per policy)
- Purple AI provides natural language investigation and threat hunting
- Hyperautomation layer for scaling beyond traditional SOAR
- Integrated into Singularity tiers (Core/Enterprise/Complete)

Source: [CrowdStrike vs SentinelOne 2025 (UnderDefense)](https://underdefense.com/blog/crowdstrike-vs-sentinelone-2025-whos-building-the-better-ai-soc-brain/)

**Microsoft Security Copilot with Guided Response**
- Copilot Guided Response (CGR): first openly discussed industry-scale guided response framework
- Each incident evaluated with TP/FP/BP prediction with confidence assessed against a precision threshold
- Agents deployed across Defender, Entra, Intune, and Purview
- Organizations report **30% reduction in MTTR**
- Available to all Microsoft 365 E5 customers

Source: [AI-Driven Guided Response for SOCs with Microsoft Copilot (arXiv)](https://arxiv.org/html/2407.09017v2)

**Torq Hyperautomation**
- Event-driven, API-first architecture delivering **5x alert throughput** over established SOAR
- Blends deterministic event-driven workflows with agentic reasoning
- Progressive automation model: SOC teams refine playbooks based on real-world performance, progressively automating more scenarios as confidence grows
- Higher-impact actions optionally require human authorization
- Asynchronous, distributed event system handling millions of concurrent events

Source: [Torq Hyperautomation Platform](https://torq.io/hyperautomation/)

**Swimlane Turbine**
- Agentic AI platform with specialized agents: Investigation Agent, Threat Intelligence Agent, MITRE ATT&CK/D3FEND Mapping Agent
- Low-code playbook builder (Turbine Canvas) for non-engineers
- Executes **25 million daily actions** for a single customer -- 17x faster than SOAR competitors
- Centralized case management consolidating alerts, observables, threat intel, analyst notes

Source: [Swimlane Turbine AI Automation Platform](https://swimlane.com/swimlane-turbine/)

**Prophet Security**
- Over **1 million autonomous investigations** in six months
- Saving an estimated **360,000 hours** of investigation time
- **10x faster response times** and **96% false positive reduction**
- Each alert investigated through structured reasoning steps with evidence-based justifications

Source: [Prophet Security: AI vs. AI (VentureBeat)](https://venturebeat.com/ai/ai-vs-ai-prophet-security-raises-30m-to-replace-human-analysts-with-autonomous-defenders)

### 2.3 Adaptive Threshold Research

**Static vs. Dynamic Thresholds.** Traditional security tools use static thresholds that fail to account for changing environments. Adaptive thresholding dynamically adjusts decision boundaries in real time based on contextual and historical data, offering improved detection accuracy, reduced false positives, and greater flexibility.

**Context-Aware Dynamic Thresholds** adjust decision boundaries based on situational factors:
- More permissive thresholds in high-risk scenarios (active incident, elevated threat level)
- More restrictive settings for routine activity
- Adjustments for time of day, user role, asset sensitivity

**Novel Statistical Approaches.** Recent frameworks like Segmented Confidence Sequences (SCS) and Multi-Scale Adaptive Confidence Segments (MACS) use statistical online learning and segmentation principles for local, contextually sensitive adaptation while maintaining guarantees on false alarm rates even under evolving distributions.

**Threat Intelligence Integration.** Future calibration systems will integrate with threat intelligence feeds, automatically adjusting thresholds based on emerging threat campaigns. When intelligence indicates active exploitation of a vulnerability, thresholds for related detection rules temporarily lower.

Sources:
- [Adaptive Thresholding in ML-Based Cloud Anomaly Detection Systems (ResearchGate)](https://www.researchgate.net/publication/391449432_Adaptive_Thresholding_in_ML-Based_Cloud_Anomaly_Detection_Systems)
- [Online Adaptive Anomaly Thresholding with Confidence Sequences (ICML 2024)](https://dl.acm.org/doi/10.5555/3692070.3693987)
- [A Confidence-Aware Machine Learning Framework for Dynamic Security Assessment (IEEE)](https://ieeexplore.ieee.org/document/9354032/)
- [Adaptive Threshold for Threat Detection (ManageEngine)](https://www.manageengine.com/log-management/adaptive-threshold.html)
- [What Is Adaptive Thresholding? (Splunk)](https://www.splunk.com/en_us/blog/learn/adaptive-thresholding.html)

---

## 3. Risk-Based Decision Frameworks

### 3.1 Decision Factor Matrix

The following factors should be evaluated for every automated response decision:

| Factor | Low Risk (Auto-OK) | Medium Risk (Semi-Auto) | High Risk (Human Required) |
|--------|--------------------|-----------------------|---------------------------|
| **Alert Confidence** | >95% with multiple corroborating signals | 70-95% with some context | <70% or single indicator |
| **Asset Criticality** | Development/test systems | Internal business systems | Production, customer-facing, crown jewels |
| **Action Reversibility** | Fully reversible (block IP, quarantine email) | Partially reversible (isolate host) | Irreversible (wipe, terminate, legal hold) |
| **Business Impact** | No user impact | Limited user disruption | Revenue impact, customer-facing outage |
| **Blast Radius** | Single endpoint | Subnet/team | Organization-wide or cross-org |
| **Compliance Sensitivity** | Non-regulated data | Internal compliance | PCI/HIPAA/SOC2 regulated data |

### 3.2 Automated vs. Human Response Decision Matrix

**Safe for Full Automation (Level 3-4):**
- Enrichment: IOC lookups, reputation checks, WHOIS, passive DNS
- Low-risk containment: Quarantining phishing emails, blocking known-malicious IPs at the firewall
- Ticket creation and routing
- Evidence collection and timeline building
- Deduplication and alert correlation

**Requires Human Approval (Level 2):**
- Host isolation from the network
- Disabling user accounts
- Blocking internal IPs or domains
- Modifying firewall rules for production segments
- Initiating forensic imaging

**Requires Human Decision (Level 0-1):**
- Wiping or reimaging production systems
- Initiating legal holds or breach notifications
- Engaging law enforcement
- Communicating to executives or customers
- Any action affecting regulated data (PHI, PCI cardholder data)

### 3.3 Regulatory Constraints on Automation

**SOC 2** requires:
- Documented human oversight of security controls
- Audit logs recording what data was processed and by whom
- Incident response plans reviewed, updated, and tested annually
- Evidence that controls are in place and working -- cannot be fully automated

**HIPAA** requires:
- Encryption and access controls for protected health information (PHI)
- Breach notification procedures with specific timelines
- Human accountability for decisions affecting PHI
- Documented risk assessment processes

**PCI-DSS** consists of:
- 12 core security requirements covering encryption, access control, network security
- Regular security testing requirements
- Specific logging and monitoring mandates
- Change management controls requiring human review

**Key Principle:** No regulatory framework currently permits fully autonomous destructive actions on regulated data without human accountability. Any automation system must maintain a clear chain of human authorization for high-impact decisions.

Sources:
- [SOC 2 Compliance Requirements (Cybercrest)](https://www.cybercrestcompliance.com/blog/soc-2-compliance-requirements)
- [14 Security Frameworks and Standards (Drata)](https://drata.com/blog/security-frameworks)
- [6 Key Cybersecurity Standards (Invensis)](https://www.invensis.net/blog/key-cybersecurity-standards)
- [NIST SP 800-61r3: Incident Response Recommendations (NIST)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

### 3.4 NIST Framework Alignment

NIST SP 800-61 Revision 3 (finalized April 2025) supersedes the previous lifecycle model, mapping incident response to the CSF 2.0 five core functions: **Identify, Protect, Detect, Respond, and Recover**. This aligns well with an automation framework where different autonomy levels can be assigned to each function:

- **Identify/Protect:** High autonomy appropriate (asset inventory, vulnerability scanning)
- **Detect:** High autonomy for triage and correlation, human verification for novel threats
- **Respond:** Graduated autonomy based on action reversibility and asset criticality
- **Recover:** Human oversight required for restoration decisions affecting business operations

Source: [NIST SP 800-61r3 (NIST CSRC)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

---

## 4. Measurable Outcomes

### 4.1 Key SOC Metrics and Benchmarks

**Mean Time to Detect (MTTD)**
- Top-performing teams: **30 minutes to 4 hours**
- Industry leaders benchmark phishing detection to **under 1 hour**
- SOAR automates the first 5 minutes of investigation, delivering pre-vetted, context-rich incidents

**Mean Time to Respond (MTTR)**
- Industry cross-sector average (2023): **~72 hours**
- Acceptable range: **2-4 hours** (shorter indicates lower overall risk)
- Severity-based targets: Critical incidents **under 8 hours**, High-severity **24-48 hours**
- Organizations with SOAR achieve MTTR **60-90% lower** than those without
- Microsoft Security Copilot users report **30% MTTR reduction**
- CrowdStrike Charlotte AI claims to save **40+ hours per week** of SOC workload

**False Positive Handling Rate**
- Industry average: **~53% of alerts are false positives** (Devo SOC Performance Report)
- Analysts spend **>25% of their time** handling false positives (Trend Micro)
- Optimal FPR benchmarks by severity: Critical <25%, High <50%, Medium <75%
- Advanced tools with fine-tuned detection achieve **<1% FPR**
- Prophet Security claims **96% false positive reduction**

**Analyst Handling Capacity**
- Average organizations face **960 alerts/day** (enterprises: 3,000+)
- 85% of SOC analysts cite endpoint security alerts as primary trigger (SANS 2025)
- Automation reduces manual investigation time by **60-80%**
- Pre-defined response sequences reduce remediation time variation by **42%** (Gartner)

**Escalation and Triage Efficiency**
- 42% of SOCs admit to dumping all data into SIEM without a retrieval plan (SANS 2025)
- 79% of SOCs operate 24/7 but 69% still rely on manual reporting
- 62% say organizations are not doing enough to retain talent

Sources:
- [SOC Metrics & KPIs That Matter (Prophet Security)](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more)
- [SOC Metrics: MTTD, MTTR and Security KPIs (nFlo)](https://nflo.tech/knowledge-base/soc-metrics-mttd-mttr-kpi-security/)
- [Essential Metrics to Track for SecOps (Fortinet)](https://www.fortinet.com/resources/cyberglossary/secops-metrics)
- [Mastering MTTR (Palo Alto Networks)](https://www.paloaltonetworks.com/cyberpedia/mean-time-to-repair-mttr)
- [SANS 2025 SOC Survey (Yahoo Finance)](https://finance.yahoo.com/news/sans-2025-soc-survey-exposes-131400675.html)

### 4.2 Demonstrating Measurable Improvement (Portfolio Value)

For RunbookPilot as a portfolio project, the following metrics are most compelling:

**Tier 1: Direct Measurement (easiest to demonstrate)**
- Time from alert to first automated enrichment action (target: <30 seconds)
- Number of automated enrichment steps per alert (target: 5-15 steps)
- False positive auto-closure rate with accuracy (target: >90% accuracy)
- Time saved per alert investigation (target: 60-80% reduction)

**Tier 2: Derived Metrics (requires simulation or test data)**
- MTTR improvement vs. manual baseline
- Analyst capacity multiplier (alerts handled per analyst shift)
- Escalation accuracy (correctly escalated vs. total escalations)
- Playbook completion rate (automated steps completed without human intervention)

**Tier 3: Business Impact (projected/modeled)**
- Cost per incident resolved
- Analyst burnout reduction (fewer manual repetitive tasks)
- Coverage improvement (24/7 automated triage vs. shift-dependent)

---

## 5. State of the Art (2025-2026)

### 5.1 Key Research Papers

**1. "Toward Robust Security Orchestration and Automated Response in Security Operations Centers with a Hyper-Automation Approach Using Agentic Artificial Intelligence" (MDPI, 2025)**
- Proposes IVAM Framework (Investigation-Validation-Active Monitoring) incorporating MITRE ATT&CK, NIST CSF, and Quantitative Risk Assessment
- Demonstrates multi-step reasoning AI agents with shared memory, external tool integration, and HITL functionality
- Enables zero-shot task execution and dynamic playbook generation, surpassing static/no-code SOAR models

Source: [MDPI Information 16(5)](https://www.mdpi.com/2078-2489/16/5/365)

**2. "AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation" (MDPI, November 2025)**
- Comprehensive survey of how LLMs and autonomous AI agents enhance SOC capabilities
- Covers: log summarization, alert triage, threat intelligence, incident response, report generation, asset discovery, vulnerability management

Source: [MDPI Platforms 5(4)](https://www.mdpi.com/2624-800X/5/4/95)

**3. "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes" (arXiv, January 2026)**
- Discusses agentic AI amplifying human capacity through automated alert triage, autonomous incident response, scalable red-blue simulation
- Identifies remaining gaps in benchmarks and evaluation pipelines for agentic AI security

Source: [arXiv:2601.05293](https://arxiv.org/html/2601.05293v1)

**4. "Adaptive Alert Prioritisation in SOCs via Learning to Defer with Human Feedback" (arXiv, 2025)**
- Learning to Defer with Human Feedback (L2DHF) uses Deep Reinforcement Learning from Human Feedback
- Achieves **13-16% higher alert prioritization accuracy** for critical alerts
- Reduces misprioritizations by **98%** for high-category alerts
- Decreases deferrals by **37%**, directly reducing analyst workload

Source: [arXiv:2506.18462](https://arxiv.org/html/2506.18462)

**5. "A Review of Agentic AI in Cybersecurity: Cognitive Autonomy, Ethical Governance, and Quantum-Resilient Defense" (PMC, 2025)**
- Synthesizes literature from 2005-2025 across cognitive autonomy, ethical governance, and quantum-resilient defense
- Comprehensive narrative review integrating academic, industry, and policy sources

Source: [PMC/NIH](https://pmc.ncbi.nlm.nih.gov/articles/PMC12569510/)

**6. "Transforming Cybersecurity with Agentic AI to Combat Emerging Cyber Threats" (ScienceDirect, 2025)**
- Explores agentic AI for decision-making, incident response, and threat detection in SOCs
- Addresses practical implementation challenges

Source: [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0308596125000734)

### 5.2 Vendor Landscape: Who's Solving HITL Best?

| Vendor | Approach | Strengths | HITL Model |
|--------|----------|-----------|------------|
| **CrowdStrike** (Charlotte) | Multi-agent agentic SOAR | Deep Falcon platform integration, deterministic + adaptive workflows | Confidence-based autonomous triage with analyst guardrails |
| **Torq** | Hyperautomation | Event-driven 5x throughput, progressive automation | Confidence grows with playbook refinement; human auth for high-impact |
| **Swimlane** (Turbine) | Agentic AI + low-code | 25M daily actions, specialized agents | Investigation/TI/MITRE agents with centralized case management |
| **Prophet Security** | Autonomous investigation | 1M+ investigations, 96% FP reduction | AI triage with evidence-based justifications for analyst review |
| **Dropzone AI** | Autonomous analyst emulation | Structured reasoning mimicking elite analysts | Natural language summaries with evidence for escalation decisions |
| **Microsoft** (Security Copilot) | Guided response | Ecosystem integration, CGR framework | TP/FP/BP classification with confidence thresholds |
| **SentinelOne** | Tiered autonomy | Three-tier manual/semi/autonomous model | Policy-driven automation with Purple AI investigation |
| **Radiant Security** | Adaptive AI SOC | Continuous feedback loops, post-deployment learning | Analyst corrections feed back into model; judgment stays with humans |
| **Sophos** | MDR with HITL | Human-verified MDR | AI augments analysts; transparency into human decision points |

### 5.3 Industry Direction (2026-2027)

**Gartner Declares SOAR Obsolete.** Gartner has officially retired the SOAR Magic Quadrant. Traditional SOAR is at the "trough of disillusionment." The future is **AI-driven automated incident response** on the "Slope of Enlightenment." SOAR as a pure-play technology is being consumed into SIEM, XDR, and MDR platforms.

Sources:
- [Gartner Says "SOAR Is Obsolete" (Torq)](https://torq.io/blog/gartner-automated-incident-response/)
- [Saying Goodbye to SOAR (Blink)](https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations)

**Sophos 2026 Predictions:**
- MDR services will be forced to **prove** -- not just claim -- that humans are still in the loop
- Buyers will demand transparency into who is monitoring, who decides, and where human judgment applies
- MDR services relying solely on automation will struggle to earn trust during ambiguous, high-impact incidents
- The strongest providers use AI to **augment** analysts rather than replace them

Source: [Human-in-the-Loop Security Will Define 2026 (Sophos)](https://www.sophos.com/en-us/blog/human-in-the-loop-security-will-define-2026-predictions-from-sophos-experts)

**Key Trends for 2026-2027:**
1. **Agentic SOAR replaces static playbooks** -- dynamic, context-aware workflows that adapt in real time
2. **Multi-agent architectures** -- specialized AI agents coordinated by an orchestrator (CrowdStrike's "droids" model)
3. **Continuous learning loops** -- analyst feedback directly improves AI classification in production
4. **Proof of human oversight** -- customers demand evidence of human involvement, not just automation claims
5. **52% of executives** in GenAI-using organizations have AI agents in production; 46% for security operations
6. **Convergence** -- SOAR, SIEM, XDR, and MDR merging into unified platforms

### 5.4 Open Problems That Remain Unsolved

1. **Evaluation Gap.** Results from pre-deployment AI tests do not reliably predict real-world performance. No standardized benchmarks exist for agentic AI security systems.

2. **AI Agent Identity and Governance.** Organizations are creating autonomous digital workforces operating beyond traditional identity controls. Excessive AI agent privileges, outdated identity frameworks, and limited monitoring create a new class of insider threat -- the "Triple Threat" of 2026.

3. **Data Poisoning of Security AI.** Adversaries can corrupt training data to create hidden backdoors and untrustworthy models. People who understand data and people who secure infrastructure operate in separate silos.

4. **Cascading Multi-Agent Failures.** Research from December 2025 found that cascading failures propagate through agent networks faster than traditional incident response can contain them.

5. **Trust Calibration at Scale.** No reliable method exists to dynamically calibrate human trust in AI recommendations across diverse SOC environments and analyst experience levels.

6. **Explainability Under Pressure.** During active incidents, analysts need to understand AI reasoning quickly. Current XAI approaches are too slow or too abstract for real-time incident response.

7. **Cross-Organization Knowledge Transfer.** Feedback loops and learned models are organization-specific. No mechanism exists for safely sharing defensive AI improvements across organizations without exposing sensitive internal data.

Sources:
- [2026 Report: Extended Summary for Policymakers (International AI Safety Report)](https://internationalaisafetyreport.org/publication/2026-report-extended-summary-policymakers)
- [The "Triple Threat" of 2026 (EMA)](https://www.enterprisemanagement.com/product/the-triple-threat-of-2026-why-your-ai-workforce-is-your-biggest-security-blind-spot/)
- [AI Agent Attacks in Q4 2025 (eSecurity Planet)](https://www.esecurityplanet.com/artificial-intelligence/ai-agent-attacks-in-q4-2025-signal-new-risks-for-2026/)

---

## 6. Architecture Patterns for HITL Systems

### 6.1 Event-Driven Architecture for Security Automation

The consensus architecture for modern security automation is **event-driven** with the following components:

```
[Alert Sources] --> [Event Bus/Message Queue] --> [Enrichment Pipeline] --> [Decision Engine] --> [Action Router]
     |                       |                          |                        |                    |
   SIEM/EDR/           Kafka/Redis/              IOC lookups,              Confidence           Auto/Semi/
   Cloud/IDS           Event Grid              reputation,               scoring +             Manual
                                               context                  risk matrix            routing
```

**Key Architectural Principles:**
- **Asynchronous processing** -- decouples alert ingestion from investigation from response
- **Event sourcing** -- every state change is an immutable event, enabling full audit trail reconstruction
- **Complex Event Processing (CEP)** -- patterns of simple events infer complex threat scenarios
- **Feedback loops** -- processed events generate new events, creating chains of detection-response cycles

Sources:
- [Event-Driven Architecture (IBM)](https://www.ibm.com/think/topics/event-driven-architecture)
- [Event-Driven Architecture Patterns (Solace)](https://solace.com/event-driven-architecture-patterns/)
- [Event-Driven Architecture (Confluent)](https://www.confluent.io/learn/event-driven-architecture/)

### 6.2 Decision Engine Patterns

**Pattern 1: Rule-Based (Deterministic)**
- Static playbooks with if/then/else logic
- Pros: Predictable, auditable, fast
- Cons: Brittle, cannot handle novel threats, high maintenance
- Best for: Well-understood, high-confidence, reversible actions

**Pattern 2: ML-Based (Probabilistic)**
- Classification models that score alerts and predict optimal actions
- Pros: Handles novel patterns, improves over time
- Cons: Black box, requires training data, calibration drift
- Best for: Triage, prioritization, pattern recognition

**Pattern 3: Hybrid (Recommended for RunbookPilot)**
- Combines deterministic rules for well-known scenarios with ML for novel/ambiguous cases
- CrowdStrike Charlotte exemplifies this: "bridges the precision of deterministic automation with the adaptability of intelligent agents"
- Rule-based engine handles the "known knowns" at full automation speed
- ML engine handles the "known unknowns" with confidence-scored recommendations
- Human handles the "unknown unknowns" with full context provided by both engines

**Pattern 4: Agentic (Emerging)**
- LLM-based agents that reason about alerts, generate investigation plans, and execute tool calls
- IVAM Framework (MDPI 2025) demonstrates multi-step reasoning agents with shared memory
- Pros: Highly flexible, can handle novel scenarios, natural language explanations
- Cons: Hallucination risk, latency, cost, harder to audit
- Best for: Complex investigations requiring multi-step reasoning

### 6.3 Feedback Loop Architecture

The state-of-the-art feedback architecture (based on Radiant Security's published approach and the L2DHF research):

```
[Alert] --> [AI Triage] --> [Classification + Confidence] --> [Routing Decision]
                                                                    |
                                            +-------------------------------------------+
                                            |                    |                      |
                                        [Auto-Close]      [Analyst Queue]        [Escalation]
                                            |                    |                      |
                                        [Verify via             [Analyst              [Analyst
                                         sampling]            Disposition]           Decision]
                                            |                    |                      |
                                            +-------------------------------------------+
                                                                    |
                                                            [Feedback Store]
                                                                    |
                                                    +-------------------------------+
                                                    |                               |
                                            [Model Fine-Tuning]            [Threshold Adjustment]
                                            (contextual params             (adaptive calibration)
                                             adjust; base weights
                                             remain stable)
```

**Key Implementation Details:**

1. **Incremental Learning:** Base model weights remain stable while contextual parameters adjust through incremental updates. This prevents catastrophic forgetting while adapting to the organization's specific environment.

2. **Transparency Chain:** When an analyst reclassifies recurring alerts as non-threats, the model adjusts -- those alerts appear with lower severity under a new category reflecting the feedback. Every change is traceable.

3. **Performance Metrics:** L2DHF experiments demonstrate 13-16% higher accuracy for critical alerts, 98% reduction in misprioritizations for high-category alerts, and 37% fewer deferrals to human analysts.

4. **Feedback Flywheel:** Fewer false positives create cleaner data, which improves the model, which produces fewer false positives. Each cycle compounds the previous one.

Sources:
- [Continuous Feedback Loops (Radiant Security)](https://radiantsecurity.ai/blog/continuous-feedback-loops/)
- [Continuous Feedback Loops (The Hacker News)](https://thehackernews.com/expert-insights/2025/11/continuous-feedback-loops-why-training.html)
- [Adaptive Alert Prioritisation via L2DHF (arXiv)](https://arxiv.org/html/2506.18462)

### 6.4 Audit Trail and Explainability Architecture

**Immutable Decision Log.** Every automated and human decision must be recorded with:
- Timestamp (high-precision)
- Decision maker (AI agent ID or human analyst ID)
- Input context (alert data, enrichment results, confidence scores)
- Decision rationale (rule matched, model explanation, human notes)
- Action taken
- Outcome (success/failure, follow-up required)

**Explainability Requirements by Autonomy Level:**

| Level | Explainability Requirement | Implementation |
|-------|---------------------------|----------------|
| Auto-close (L3-4) | Post-hoc sampling audit | Batch review of auto-closed alerts with accuracy metrics |
| Semi-auto (L2) | Pre-action explanation | Natural language summary of why action is recommended |
| Manual (L0-1) | Full investigation context | Complete evidence chain, timeline, and analyst decision space |

**Regulatory Alignment:**
- GDPR requires records of data processing and automated decision-making
- SOC 2 requires evidence that controls are working as intended
- Audit trails must be comprehensive, queryable, retained, access-controlled, and demonstrably connected to risk management

**Implementation Pattern:**
- API-based integration consolidates logs from disparate systems into centralized repository
- Immutable append-only log (event sourcing pattern)
- Each AI agent action recorded with full context
- Human overrides logged with justification
- Periodic audit reports auto-generated for compliance

Sources:
- [Audit Trails for Agents (Adopt AI)](https://www.adopt.ai/glossary/audit-trails-for-agents)
- [The AI Audit Trail (Medium)](https://medium.com/@kuldeep.paul08/the-ai-audit-trail-how-to-ensure-compliance-and-transparency-with-llm-observability-74fd5f1968ef)
- [Audit Logs in AI Systems (Latitude)](https://latitude-blog.ghost.io/blog/audit-logs-in-ai-systems-what-to-track-and-why/)
- [Audit Trails and Explainability for Compliance (Medium)](https://lawrence-emenike.medium.com/audit-trails-and-explainability-for-compliance-building-the-transparency-layer-financial-services-d24961bad987)

---

## 7. Implications for RunbookPilot

### 7.1 Positioning in the Market

RunbookPilot sits in a validated and rapidly growing market space:
- Gartner declares traditional SOAR obsolete -- the market is being **recreated** around AI-driven automated incident response
- The HITL problem is the **central unsolved challenge** that every vendor is racing toward
- Sophos predicts HITL transparency will **define 2026** -- buyers demand proof of human involvement
- The 4-5 million person cybersecurity workforce gap creates intense demand for force-multiplier tools

**RunbookPilot's differentiator:** Unlike vendors building general-purpose AI SOC platforms, RunbookPilot focuses specifically on the **runbook execution layer** with graduated HITL -- the operational gap between "detection fired" (DetectForge's output) and "incident resolved."

### 7.2 Recommended Architecture Decisions

Based on this research, the following architectural decisions are recommended for RunbookPilot:

1. **Five-Level Autonomy Model** (aligned with Mohsin et al. framework)
   - L0: Manual runbook (checklist mode)
   - L1: AI-assisted (AI suggests next steps, human executes)
   - L2: Semi-autonomous (AI executes with human approval gates)
   - L3: Supervised autonomous (AI executes, human monitors dashboard)
   - L4: Fully autonomous (AI executes within defined guardrails)

2. **Hybrid Decision Engine**
   - Deterministic rules for well-understood runbook steps
   - Confidence scoring for ambiguous situations
   - Adaptive thresholds that adjust based on feedback and context

3. **Event-Driven Core Architecture**
   - Message queue for decoupled, asynchronous processing
   - Event sourcing for full audit trail
   - Webhook-based integration with DetectForge and external tools

4. **Continuous Feedback Loop**
   - Analyst dispositions feed back into confidence calibration
   - Progressive automation: start at L1-L2, earn trust to L3-L4
   - Every analyst override is a training signal

5. **Compliance-First Audit Trail**
   - Immutable decision log with full context
   - Pre-action explainability for semi-automated steps
   - Auto-generated compliance reports

### 7.3 Key Metrics to Track

RunbookPilot should instrument these metrics from day one:

| Metric | Description | Target |
|--------|-------------|--------|
| Time to First Action | Seconds from alert to first automated enrichment | <30s |
| Runbook Completion Rate | % of runbook steps completed without human intervention | >70% for L3+ |
| Analyst Approval Latency | Time between AI recommendation and human approval | <5 min for L2 |
| Confidence Calibration | How well confidence scores predict actual outcomes | >85% correlation |
| False Action Rate | % of automated actions that were incorrect | <5% |
| Feedback Loop Velocity | How quickly analyst corrections improve model performance | Measurable within 1 week |
| MTTR Delta | MTTR with RunbookPilot vs. manual baseline | >50% reduction |

### 7.4 Research-Backed Design Principles

1. **Start with augmentation, not autonomy.** The literature consistently shows that human-in-the-loop outperforms either full automation or full manual processes. Begin at L1-L2 and earn trust.

2. **Make confidence visible.** Every AI recommendation should display its confidence score and the factors contributing to it. Analysts need to calibrate their trust in the system.

3. **Reversibility determines automation level.** Use action reversibility as the primary gate for automation. Reversible actions (block IP, quarantine email) can be automated at lower confidence thresholds than irreversible actions (wipe, terminate).

4. **Feedback is the product.** The feedback loop is not a feature -- it is the core value proposition. Every analyst interaction improves the system. This compounds over time and creates a defensible moat.

5. **Prove the human is in the loop.** Following Sophos's prediction, RunbookPilot should make human decision points visible and auditable. This is both a compliance requirement and a trust-building feature.

6. **Comply by design.** Build SOC 2, HIPAA, and PCI-DSS audit trail requirements into the architecture from day one, not as an afterthought.

---

## Appendix: Source Index

### Academic Papers
1. Mohsin, A. et al. (2025). "A Unified Framework for Human-AI Collaboration in SOCs with Trusted Autonomy." [arXiv:2505.23397](https://arxiv.org/abs/2505.23397)
2. Tariq, S. et al. (2025). "Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities." [ACM Computing Surveys 57(9)](https://dl.acm.org/doi/10.1145/3723158)
3. "Towards Human-AI Teaming to Mitigate Alert Fatigue in SOCs." [ACM TOIT](https://dl.acm.org/doi/10.1145/3670009)
4. "Toward Robust SOAR in SOCs with Hyper-Automation Using Agentic AI." [MDPI Information 16(5)](https://www.mdpi.com/2078-2489/16/5/365)
5. "AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation." [MDPI Platforms 5(4)](https://www.mdpi.com/2624-800X/5/4/95)
6. "A Survey of Agentic AI and Cybersecurity." [arXiv:2601.05293](https://arxiv.org/html/2601.05293v1)
7. "Adaptive Alert Prioritisation via Learning to Defer with Human Feedback." [arXiv:2506.18462](https://arxiv.org/html/2506.18462)
8. "A Review of Agentic AI in Cybersecurity." [PMC/NIH](https://pmc.ncbi.nlm.nih.gov/articles/PMC12569510/)
9. "Transforming Cybersecurity with Agentic AI." [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0308596125000734)
10. "AI-Driven Guided Response for SOCs with Microsoft Copilot." [arXiv:2407.09017](https://arxiv.org/html/2407.09017v2)
11. "A Confidence-Aware ML Framework for Dynamic Security Assessment." [IEEE Xplore](https://ieeexplore.ieee.org/document/9354032/)
12. "Online Adaptive Anomaly Thresholding with Confidence Sequences." [ICML 2024](https://dl.acm.org/doi/10.5555/3692070.3693987)
13. "AI-Driven Human-Autonomy Teaming in Tactical Operations." [arXiv:2411.09788](https://arxiv.org/html/2411.09788v1)

### Industry Reports and Surveys
14. [SANS 2025 SOC Survey](https://www.sans.org/white-papers/sans-2025-soc-survey)
15. [2025 SANS Detection & Response Survey (Stamus Networks Analysis)](https://www.stamus-networks.com/blog/what-the-2025-sans-detection-response-survey-reveals-false-positives-alert-fatigue-are-worsening)
16. [Gartner: SOAR Market Guide / Retirement](https://torq.io/blog/gartner-automated-incident-response/)
17. [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

### Vendor and Industry Sources
18. [CrowdStrike Charlotte Agentic SOAR](https://www.crowdstrike.com/en-us/blog/crowdstrike-leads-new-evolution-of-security-automation-with-charlotte-agentic-soar/)
19. [Sophos HITL 2026 Predictions](https://www.sophos.com/en-us/blog/human-in-the-loop-security-will-define-2026-predictions-from-sophos-experts)
20. [Torq Hyperautomation](https://torq.io/hyperautomation/)
21. [Swimlane Turbine](https://swimlane.com/swimlane-turbine/)
22. [Prophet Security](https://venturebeat.com/ai/ai-vs-ai-prophet-security-raises-30m-to-replace-human-analysts-with-autonomous-defenders)
23. [Radiant Security Feedback Loops](https://radiantsecurity.ai/blog/continuous-feedback-loops/)
24. [Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/microsoft-security-copilot)
25. [Dropzone AI](https://www.dropzone.ai/)
26. [Red Canary IR Containment](https://redcanary.com/blog/ir-containment-isolation/)
27. [Prophet Security AI SOC](https://www.prophetsecurity.ai)
28. [SACR AI SOC Market Landscape 2025](https://softwareanalyst.substack.com/p/sacr-ai-soc-market-landscape-for)

### Metric Sources
29. [SOC Metrics & KPIs (Prophet Security)](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more)
30. [SOC Metrics: MTTD, MTTR (nFlo)](https://nflo.tech/knowledge-base/soc-metrics-mttd-mttr-kpi-security/)
31. [MTTD & MTTR KPI (World Informatix)](https://worldinformatixcs.com/2025/12/04/mttd-mttr-kpi/)
32. [Alert Fatigue (Dropzone AI)](https://www.dropzone.ai/glossary/alert-fatigue-in-cybersecurity-definition-causes-modern-solutions-5tz9b)
33. [SOC Analyst Burnout (Abnormal AI)](https://abnormal.ai/blog/soc-analyst-burnout-ai)
34. [False Positives (OP Innovate)](https://op-c.net/blog/why-false-positives-killing-security-teams/)
35. [99% False Positives (USENIX Security)](https://www.usenix.org/system/files/sec22summer_alahmadi.pdf)

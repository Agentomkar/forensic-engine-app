# Forensic Evidence Intelligence Agent (FEIA) - Creating Impact for Bharat
### *Autonomous digital evidence investigation for India's digital economy*

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Framework-Flask%20%2B%20SocketIO-000000.svg?style=flat&logo=flask)](https://flask.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat&logo=docker&logoColor=white)](https://www.docker.com)
[![Machine Learning](https://img.shields.io/badge/ML-Dual%20RandomForest%20%2B%20SHAP-F7931E.svg?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-E63946.svg?style=flat)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Android app:** the Play Store client ("FEIA Scam Check") lives in [`mobile/`](mobile/). Build, deploy and publishing steps are in [PLAYSTORE.md](PLAYSTORE.md).

---

## 1. Project Overview

The **Forensic Evidence Intelligence Agent (FEIA)** transforms digital forensics from manual multi-tool clicking into **autonomous investigation** for India's digital economy. A suspicious bank message, a fraudulent UPI or KYC link, and a compromised business mailbox can each leave evidence across email headers, URLs, reputation sources, and browser history. FEIA brings those signals into one traceable workflow: it plans an investigation, invokes relevant forensic tools, follows leads found in evidence, correlates results, and prepares an explainable report and response playbook for human review.

This is a Bharat-scale challenge. The project framing highlights **622M+ Indian internet users at risk** and **₹8,000+ crore in annual cyber-fraud losses**. India's mobile-first financial services and growing online commerce create enormous opportunity, but also make phishing and account compromise consequential for citizens and businesses. At the same time, **63M+ SMEs** lack the resources to operate dedicated security operations teams, while **500+ fintech startups** need ways to scale investigation capacity without multiplying manual review.

FEIA is designed to help close that first-response gap—not replace CERT-In, law enforcement, or trained incident responders. It accepts supported email, URL, and browser-history evidence; records its investigative actions; distinguishes observed evidence from model assessment; and keeps disruptive response actions behind human approval. The goal is practical: make structured digital investigation more accessible to Indian organizations, from financial institutions to resource-constrained businesses, and support trust in the services on which Digital India depends. National statistics are challenge framing and should be validated against dated primary sources before external use.

---

## 2. Why This Matters for Bharat

India's cyber threat landscape reflects the speed and scale of its digital adoption. Citizens receive bank-impersonation messages, fake KYC notices, QR-code and UPI lures, fraudulent customer-support numbers, and delivery or government-service links through channels they use every day. Businesses face supplier impersonation, invoice diversion, credential theft, and malicious email attachments. One compromised account can harm a household or interrupt a small firm's cash flow; a widespread campaign can affect trust in digital services far beyond a single victim.

The challenge framing cites **240,000+ cyber incidents reported annually to CERT-In** and **₹8,000+ crore in annual cyber-fraud losses**. These figures underline the need for faster investigation, but incident counts and loss totals vary by reporting period and definition. They should be cited to current official publications before being treated as audited totals. The same care applies to the estimate that **95% of SMEs lack dedicated security teams**: millions of Indian small businesses rely on general IT support or external help rather than analysts who can investigate every alert.

This capacity gap matters to **Digital India**. Public services, digital identity-linked journeys, online payments, and government platforms depend on citizens believing that digital access is dependable. Government IT departments need consistent ways to triage suspicious evidence, preserve investigation context, and escalate credible incidents to authorized responders. An investigation assistant cannot replace security controls, CERT-In directions, or an incident-response plan, but it can help reduce the time between a suspicious signal and an informed human decision.

India's fintech revolution adds urgency. Banks, NBFCs, payment providers, and more than **500 fintech startups** operate in a fast-moving ecosystem where high transaction volumes and mobile-first customer interactions create substantial monitoring needs. Yet an alert is not automatically a forensic case: teams still need to correlate sender identity, links, reputation, and user activity before taking action. Automating evidence collection and first-pass analysis can help specialists focus on complex fraud and confirmed incidents.

For SMEs and mid-market firms, the choice is often not between two SOC vendors; it is between affordable, structured triage and having no dedicated investigation capability. Bharat needs practical cyber defense that can serve both large institutions and organizations without a round-the-clock SOC. That is the local problem FEIA addresses.

---

## 3. The Agent's Impact

FEIA targets the repetitive first phase of investigation: identifying what arrived, extracting relevant indicators, checking supporting evidence, and assembling a reviewable case. Project planning figures compare **25–45 minutes of manual triage** with **1.8–3.2 seconds of automated processing**; a 2.1-second example is approximately **99.9% less processing time** than a 45-minute manual baseline. These are workflow targets, not a measured end-to-end resolution guarantee. Evidence collection, reputation-service latency, analyst review, and response approvals take additional time and must be measured in pilots.

For SMEs, an illustrative shared-service model proposes a **₹50,000 one-time setup** for a consortium, compared with an indicative traditional SOC setup estimate of **₹5–10 lakh** plus managed-security costs that may reach **₹1–2 lakh per month**. Actual prices vary by coverage and provider; the shared model also needs secure tenant separation, support, and operational validation. The point is to explore a lower entry barrier—not claim that a ₹50,000 deployment is equivalent to a full enterprise SOC.

Sector savings are also scenario estimates, not realized outcomes. The fintech impact model estimates **₹2.25–2.40 crore per month** in gross savings if 500 startups adopted the assumed workflow and cost structure. For banking, the documented scenario yields **₹24–32 lakh per participating institution annually**; at 500 institutions that is **₹120–160 crore per year**, not ₹1,600 crore. These calculations exclude adoption and integration costs and require pilot validation.

By automating routine evidence handling, the agent can free analysts for complex investigations, incident coordination, and control improvement. In law-enforcement contexts, structured evidence summaries may support handoffs and prioritization, but do not determine guilt or replace evidentiary standards. The intended impact is better use of human expertise and more accessible, accountable investigation across Bharat.

---

## 4. Key Capabilities

FEIA is built around a bounded investigation loop that can adapt to what the evidence reveals. It accepts supported email, URL, and browser-history inputs; infers an investigation path; invokes specialized analysis tools; and records tool activity and findings for review. When an email contains links, the agent can autonomously dispatch URL analysis rather than waiting for an operator to extract and resubmit each lead. It correlates email authentication results, sender inconsistencies, URL structure, reputation signals, and browsing evidence into a reasoned case narrative.

The agent produces risk scores and severity labels with supporting rationale, maps relevant phishing behavior to MITRE ATT&CK, and generates response recommendations such as searching mailboxes, reviewing sign-in activity, or blocking confirmed indicators. Risk scores and model confidence are decision support, not proof. High-impact actions—including account suspension, credential resets, and broad blocking—remain subject to authorized human approval. This human-in-the-loop design is essential for protecting Indian citizens, customer services, and business operations from both cyber threats and false positives.

### Agentic capabilities

- **Evidence-aware planning:** Selects tools according to whether the input is email, URL, or browser-history evidence.
- **Autonomous lead follow-up:** Automatically investigates URLs discovered in email or browser evidence.
- **Specialized forensic tools:** Parses RFC 822 email, analyzes URL features, and inspects supported browser-history databases.
- **Cross-source correlation:** Relates independent indicators into a compound attack narrative and ATT&CK mapping.
- **Transparent risk assessment:** Combines model outputs and evidence severity into an explainable risk result.
- **Investigation lead generation:** Extracts indicators and follow-up pivots for analyst validation.
- **Workflow and playbook automation:** Builds a traceable investigation sequence and actionable response recommendations.
- **Auditable reporting:** Produces structured findings and a case execution trace for operational review.
- **Human-in-the-loop safeguards:** Requires approval before destructive or disruptive containment actions.

### Why FEIA is not a chatbot

| Chatbot or static script | Forensic Evidence Intelligence Agent |
|---|---|
| Responds with text or runs a fixed checklist | Plans tools based on evidence type and intermediate findings |
| Depends on a person to investigate every discovered link | Can automatically pivot from an email to its embedded URLs |
| Produces isolated predictions or generic advice | Correlates findings and records the basis for its conclusions |
| Does not manage response authority | Recommends actions while preserving human approval gates |

### Real-world impact metrics

| Measure | Project target or scenario | Validation required |
|---|---:|---|
| Routine analysis processing time | 1.8–3.2 seconds | Benchmark representative evidence; report external lookup and review time separately |
| Manual triage baseline | 25–45 minutes per incident | Establish organization-specific time-and-motion baseline |
| Fintech gross savings | ₹2.25–2.40 crore/month at 500 assumed adopters | Validate assumptions and subtract deployment, integration, and operating costs |
| Banking gross savings | ₹120–160 crore/year at 500 assumed institutions | Scenario arithmetic; not realized savings or a forecast |
| SME consortium setup | ₹50,000 illustrative one-time setup | Validate secure operations, support cost, and provider quotations |

See [docs/](docs/) for detailed documentation, including the [Bharat problem statement](PROBLEM_STATEMENT.md), [investigation workflow](WORKFLOW.md), and [Indian bank ROI case study](BANK_ROI_CASE_STUDY.md). Performance and financial values are planning scenarios and should not be represented as independently validated results.

---

## 5. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           AGENT INGESTION INTERFACE                             │
│       REST API (POST /api/agent/investigate)  │  FEIA Investigation Workbench  │
│       Multipart File Uploads (.eml, SQLite)    │  One-Click Scenario Presets    │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AGENT CORE DECISION ENGINE (agent_core.py)                    │
│                                                                                 │
│   ┌─────────────────────┐   ┌────────────────────────┐   ┌──────────────────┐   │
│   │    AgentPlanner     │──▶│   InvestigationState   │◀──│   Lead Queue     │   │
│   │ (Dynamic DAG Setup) │   │ (Audit Trace & Memory) │   │ (Discovered URLs)│   │
│   └─────────────────────┘   └───────────┬────────────┘   └─────────┬────────┘   │
│                                         │                          │            │
│                                         ▼                          │            │
│   ┌────────────────────────────────────────────────────────────────┴────────┐   │
│   │                 AUTONOMOUS TOOL ORCHESTRATION LAYER                     │   │
│   │                                                                         │   │
│   │  ┌────────────────────┐ ┌───────────────────┐ ┌──────────────────────┐  │   │
│   │  │ EmailForensicsTool │ │  URLForensicsTool │ │ BrowserHistoryTool   │  │   │
│   │  └─────────┬──────────┘ └─────────┬─────────┘ └──────────┬───────────┘  │   │
│   │            │                      │                      │              │   │
│   │            ▼                      ▼                      ▼              │   │
│   │  ┌───────────────────────────────────────────────────────────────────┐  │   │
│   │  │             ReputationEnrichmentTool (Threat Intelligence)        │  │   │
│   │  └───────────────────────────────────────────────────────────────────┘  │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│                                         ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    EVIDENCE CORRELATION ENGINE                          │   │
│   │     Cross-Source Synthesis  │  Confidence Calibration                   │   │
│   │     MITRE ATT&CK Alignment  │  Compounding Threat Amplification         │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│                                         ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    RISK ASSESSMENT & RECOMMENDATIONS                    │   │
│   │     Transparent Risk Tiers (LOW / MEDIUM / HIGH / CRITICAL)             │   │
│   │     Actionable Containment Playbook  │  Human-in-the-Loop Safeguards    │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           DELIVERY & AUDITING LAYER                             │
│   Structured JSON API  │  Interactive Visual DAG  │  Printable Forensic Dossier │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Dynamic Agent Workflow

```text
                 [User Investigation Request]
                              │
                              ▼
                      [Agent Planner]
            (Inspects evidence type & structure)
                              │
                              ▼
                     [Initialize Plan DAG]
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       [Email Evidence]                [URL Evidence]
               │                             │
               ▼                             ▼
     (EmailForensicsTool)           (URLForensicsTool)
               │                             │
    ┌──────────┴──────────┐                  │
    │  Extracted URLs?    │                  │
    └──────────┬──────────┘                  │
        Yes    │                             │
               ▼                             │
     [Dynamic Tool Spawn]                    │
     (URLForensicsTool)                      │
               │                             │
               └──────────────┬──────────────┘
                              │
                              ▼
                 (ReputationEnrichmentTool)
               (External IP/Domain Intel)
                              │
                              ▼
                 [Cross-Source Correlator]
            (Synthesizes Multi-Vector Signals)
                              │
                              ▼
              [MITRE ATT&CK Framework Mapping]
                              │
                              ▼
                  [Risk Assessment Engine]
               (0-100 Score + Category)
                              │
                              ▼
            [Actionable Containment Playbook]
               (Human-in-the-Loop Review)
                              │
                              ▼
            [Forensic Dossier & Trace Output]
```

1. **Understand & Ingest**: The agent receives supported evidence such as a URL, RFC 822 `.eml` content, or browser-history data, with an optional investigation instruction. Unsupported evidence types should be routed to a qualified examiner rather than treated as analyzed.
2. **Dynamic Planning**: The `AgentPlanner` analyzes the input type, initializes an `InvestigationState`, and drafts a task DAG.
3. **Primary Forensic Tool Execution**:
   - For emails: The agent invokes `EmailForensicsTool`, parsing headers, inspecting SPF/DKIM results supplied in authentication headers, checking sender alignment (`From` vs `Return-Path`), and running urgency analysis.
   - For URLs: The agent invokes `URLForensicsTool`, extracting 11+ lexical and structural features.
   - For browser history: The agent invokes `BrowserHistoryForensicsTool`, parsing SQLite tables and detecting anomalous browsing frequencies.
4. **Autonomous Lead Follow-Up**: If `EmailForensicsTool` discovers embedded URLs in the message body, the agent does **not** stop; it automatically invokes `URLForensicsTool`, which can request reputation enrichment. The report should distinguish actual external lookup results from unavailable, mocked, or unscanned responses.
5. **Cross-Source Evidence Correlation**: The `EvidenceCorrelator` analyzes the union of all extracted indicators, looking for compound threat patterns (e.g., Domain Spoofing + Credential Harvesting URL + High Urgency NLP + Known Bad TLD).
6. **MITRE ATT&CK Mapping**: Maps relevant compound discoveries to adversarial techniques:
   - `T1566.002`: Phishing - Spearphishing Link
   - `T1589.002`: Reconnaissance - Gather Victim Identity Information
   - `T1583.001`: Resource Development - Domains / Suspicious TLD
   - `T1204.001`: User Execution - Malicious Link Click
7. **Transparent Risk Scoring**: Calculates a normalized 0–100 composite threat score combining ML probabilities and deterministic indicator weights into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
8. **Actionable Containment Recommendations**: Generates concrete containment actions (firewall block rules, DNS sinkhole commands, email quarantine actions, compromised user password resets) with a mandatory **Human Review Required** flag for `HIGH`/`CRITICAL` events.
9. **Auditable Outcome**: Emits a structured JSON object and a printable HTML investigation dossier.

---

## 7. Specialized Forensic Tools

The agent coordinates four specialized forensic tools exposed via standard agent interfaces:

### 1. `EmailForensicsTool`
- **Purpose**: Comprehensive RFC 822 email parser and phishing classifier.
- **Capabilities**:
  - Parses headers, MIME boundaries, plain text, and HTML bodies.
  - Reads SPF/DKIM results reported in `Authentication-Results` and `Received-SPF`; it does not independently verify DNS authorization or cryptographically validate the DKIM signature.
  - Detects spoofing anomalies: `From` header domain vs `Return-Path` domain mismatch.
  - Extracts full `Received` IP routing hops to identify origin MTAs.
  - Urgency & Coercion NLP Analyzer using `TextBlob` sentiment polarity and security keyword detection.
  - Extracts embedded URLs and feeds them into the agent's lead queue.
  - Evaluates pre-trained `email_phishing_model.pkl` classifier.

### 2. `URLForensicsTool`
- **Purpose**: Deep lexical and structural analysis of target links.
- **Capabilities**:
  - Extracts 11+ structural features: URL length, Shannon entropy, presence of raw IP address in hostname, punycode/homoglyph detection, risky TLD analysis (`.xyz`, `.top`, `.tk`, `.buzz`, `.club`, etc.), digit ratio, hyphen count, and sensitive tokens (`login`, `verify`, `secure`, `account`, `banking`, `chase`, `paypal`, `appleid`).
  - Evaluates pre-trained `url_phishing_model.pkl` classifier.
  - Emits specific, explainable indicators with severity ratings.

### 3. `BrowserHistoryForensicsTool`
- **Purpose**: Host endpoint browser forensics for Chrome, Microsoft Edge, and Mozilla Firefox.
- **Capabilities**:
  - Analyzes SQLite database files (`History`, `places.sqlite`).
  - Safe-copy mechanism prevents `sqlite3.OperationalError: database is locked` on running browsers.
  - Extracts visited URLs, domain frequency distributions, visit timestamps, and anomalous visit spikes.
  - Identifies credential harvesting visits following phishing deliveries and forwards indicators to `URLForensicsTool`.

### 4. `ReputationEnrichmentTool`
- **Purpose**: External Threat Intelligence (OSINT) correlation.
- **Capabilities**:
  - Resolves domains to IP addresses and ASN data.
  - VirusTotal API v3 integration (reads `VT_API_KEY` from environment).
  - Deterministic high-risk network reputation engine for air-gapped or unauthenticated sandbox environments.

---

## 8. Machine Learning Models & Explainability

FEIA leverages dual specialized **RandomForest** classifiers with explainable AI (XAI) overlays:

| Model | Target Artifact | Input Vector Size | Key Features | Explainability |
| :--- | :--- | :--- | :--- | :--- |
| `url_phishing_model.pkl` | URLs / Hyperlinks | 11 Features | Length, Entropy, IP in Host, Risky TLD, Subdomains, Sensitive Tokens, Query Length | SHAP Value Feature Importance & Indicator Flags |
| `email_phishing_model.pkl` | Emails (.eml) | 10 Features | SPF Result, DKIM Result, Spoofing Flag, Urgency NLP Score, Extracted URL Count, Attachment Executable Flag | Threat Factor Attribution & Coercion Sentiment Breakdown |

- **Deterministic Fallback**: If an ML model is uncertain (probability between 0.40 and 0.60), the agent preserves uncertainty, highlights the ambiguity, and weights deterministic evidence (SPF pass/fail, verified blacklist) to prevent false positives.

---

## 9. Cross-Source Evidence Correlation & MITRE ATT&CK

The core strength of FEIA is that it **does not treat tool outputs in isolation**. It correlates findings across multiple evidence vectors:

```text
[Email Header: Spoofed From] + [Body: Urgent Wire Coercion]
                      │
                      ▼ (Agent detects embedded URL)
         [Extracted Link: .xyz Host with Raw IP]
                      │
                      ▼ (Agent triggers reputation check)
      [Reputation: Untrusted ASN & Recent Domain]
                      │
                      ▼ (Agent Correlator)
    [CRITICAL PHISHING CAMPAIGN DETECTED]
    Mapped to MITRE ATT&CK T1566.002 & T1583.001
```

### Supported Correlation Patterns:
1. **Spearphishing with Embedded Malicious Link**:
   - Header spoofing + Urgent coercion text + ML-flagged URL.
   - *MITRE ATT&CK*: `T1566.002` (Phishing: Spearphishing Link).
2. **Domain Impersonation & Brand Spoofing**:
   - Known brand mentioned in email (`Chase`, `Apple`, `PayPal`) + Link points to unaffiliated risky TLD (`.top`, `.xyz`).
   - *MITRE ATT&CK*: `T1589.002` (Gather Victim Identity Information).
3. **Suspicious Host Infrastructure**:
   - Raw IP address used in place of domain or newly registered high-risk TLD.
   - *MITRE ATT&CK*: `T1583.001` (Acquire Infrastructure: Domains).
4. **Endpoint Phishing Execution**:
   - User browser history records access to malicious link following email delivery timestamp.
   - *MITRE ATT&CK*: `T1204.001` (User Execution: Malicious Link).

---

## 10. REST API Specification

FEIA exposes a REST API for integration with bank, fintech, government, and SME investigation workflows, as well as scripts and web clients. Integrations should follow each organization's access-control, privacy, retention, and incident-response requirements.

### Endpoint: `POST /api/agent/investigate`
Starts an autonomous forensic investigation.

#### Request Format (JSON):
```bash
curl -X POST http://localhost:5000/api/agent/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "input": "From: security@apple.com\nReturn-Path: spoof@hacker.top\nSubject: Account Locked\n\nPlease visit: http://apple-verify.top/login.php",
    "instruction": "Investigate this suspicious email and check all links"
  }'
```

#### Request Format (Multipart File Upload):
```bash
curl -X POST http://localhost:5000/api/agent/investigate \
  -F "type=email" \
  -F "file=@sample_emails/phishing_appleid_locked.eml" \
  -F "instruction=Full forensic triage"
```

#### Structured Response (JSON):
```json
{
  "investigation_id": "INV-20261001-A7C8E2",
  "request_type": "email",
  "status": "COMPLETED",
  "risk_score": 88.5,
  "risk_level": "CRITICAL",
  "confidence": 0.94,
  "summary": "CRITICAL RISK: Autonomous investigation detected a targeted Spearphishing Attack (T1566.002) with high-confidence credential harvesting indicators.",
  "tools_used": [
    "EmailForensicsTool",
    "URLForensicsTool",
    "ReputationEnrichmentTool"
  ],
  "agent_actions": [
    {
      "step": 1,
      "tool_name": "EmailForensicsTool",
      "reason": "Input provided is an email message requiring RFC 822 forensic inspection.",
      "timestamp": "2026-10-01T12:11:40Z",
      "status": "SUCCESS"
    },
    {
      "step": 2,
      "tool_name": "URLForensicsTool",
      "reason": "Email message body contained 1 embedded hyperlink(s) requiring deep lexical and ML inspection.",
      "timestamp": "2026-10-01T12:11:40Z",
      "status": "SUCCESS"
    }
  ],
  "evidence": [
    {
      "category": "Header Spoofing",
      "indicator": "From vs Return-Path domain mismatch",
      "source": "EmailForensicsTool",
      "severity": "HIGH",
      "confidence": 0.95
    },
    {
      "category": "Malicious URL",
      "indicator": "http://apple-verify.top/login.php",
      "source": "URLForensicsTool",
      "severity": "CRITICAL",
      "confidence": 0.91
    }
  ],
  "correlations": [
    {
      "title": "Spearphishing Email with Embedded Malicious Link",
      "severity": "CRITICAL",
      "mitre_technique": "T1566.002",
      "description": "Email contains authentication spoofing and delivered a credential harvesting URL on a high-risk TLD."
    }
  ],
  "recommendations": [
    "Review and, if confirmed, block domain 'apple-verify.top' using the organization's approved DNS/proxy controls.",
    "Search email gateway logs for messages originating from 'spoof@hacker.top' and quarantine matching items.",
    "Force credential invalidation and MFA reset for any users who opened this message."
  ],
  "human_review_required": true,
  "workflow_dag": {
    "nodes": [ ... ],
    "edges": [ ... ]
  }
}
```

### Additional Endpoints:
- `GET /api/agent/scenarios`: Returns 5 realistic pre-packaged scenarios for live demonstration.
- `GET /api/agent/investigation/<id>`: Returns the complete stored JSON investigation state.
- `GET /api/agent/report/<id>`: Returns a standalone, executive printable/exportable HTML investigation dossier.

---

## 11. Installation & Local Setup

### System Prerequisites:
- Python 3.10 or 3.11 (Python 3.11 recommended)
- Git

### Option A: Using `uv` (Recommended)
```powershell
# 1. Clone repository
git clone https://github.com/rahamxx/new-agent-forensic.git
cd new-agent-forensic

# 2. Install dependencies & initialize virtual environment
uv venv .venv
.venv\Scripts\activate      # On Windows
# source .venv/bin/activate # On Linux/macOS

uv pip install -r requirements.txt

# 3. (Optional) Set VirusTotal API Key
$env:VT_API_KEY="your_api_key_here" # Windows PowerShell
# export VT_API_KEY="your_api_key_here" # Linux/macOS

# 4. Start the Application
python app.py
```
Open your browser at **http://localhost:5000**.

### Option B: Using Standard Python `venv`
```bash
# 1. Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 3. Run application
python app.py
```

---

## 12. Docker Build & Deployment

The application includes Docker configuration for local and controlled deployments. Production use requires organization-specific hardening, security review, monitoring, and operational validation.

### Using Docker Compose (Single Command):
```bash
# Build and run in detached mode
docker-compose up -d --build

# Inspect container status and healthcheck
docker-compose ps

# View live application logs
docker-compose logs -f
```
Access the application at **http://localhost:5000**.

### Using Standard Docker CLI:
```bash
# 1. Build Docker image
docker build -t forensic-investigation-agent .

# 2. Run container with port forwarding and environment variables
docker run -d \
  --name forensic-agent \
  -p 5000:5000 \
  -e VT_API_KEY="" \
  --restart unless-stopped \
  forensic-investigation-agent

# 3. Test Container Health
curl -f http://localhost:5000/api/agent/scenarios
```

---

## 13. Live Demonstration Guide

For a live demonstration of **FEIA**, use the integrated **AI Agent Workbench**:

### Step 1: Open the Workbench
1. Navigate to **http://localhost:5000** in your web browser.
2. Click the **"AI Agent Workbench"** tab in the top navigation bar or the sidebar link marked with the glowing green `AGENTIC` badge.

### Step 2: Select a Preset Scenario
The workbench provides 5 one-click scenarios illustrating the agent's dynamic reasoning:

1. **Scenario 1: Apple ID Locked - Foreign Login Alert** (`Email + Embedded URL`)
   - *What the Agent Does*: Ingests raw `.eml` email $\rightarrow$ detects SPF/DKIM fail & sender spoofing $\rightarrow$ autonomously discovers link `http://apple-verify.top/login.php` $\rightarrow$ triggers `URLForensicsTool` and `ReputationEnrichmentTool` $\rightarrow$ identifies `.top` TLD and credential harvesting tokens $\rightarrow$ correlates compound attack $\rightarrow$ triggers `CRITICAL` risk with containment playbook.
2. **Scenario 2: Chase Bank Wire Fraud Alert** (`Email + Multi-URL with Raw IP`)
   - *What the Agent Does*: Extracts two separate hyperlinks $\rightarrow$ analyzes each discovered link $\rightarrow$ flags a raw IP address endpoint as a high-risk indicator $\rightarrow$ may map the email-delivered link to `T1566.002`.
3. **Scenario 3: PayPal Credential Harvesting Portal** (`Standalone Malicious URL`)
   - *What the Agent Does*: Evaluates URL length, Shannon entropy, and typosquatting tokens $\rightarrow$ extracts 4 high-severity indicators $\rightarrow$ issues `MEDIUM/HIGH` warning.
4. **Scenario 4: Compromised Workstation History** (`Browser History`)
   - *What the Agent Does*: Analyzes SQLite browsing history $\rightarrow$ identifies anomalous browsing sessions to phishing infrastructure $\rightarrow$ correlates endpoint execution.
5. **Scenario 5: Legitimate GitHub Security Alert** (`Legitimate Control`)
   - *What the Agent Does*: Reads SPF/DKIM results supplied in the email's authentication headers $\rightarrow$ evaluates the sender and URL indicators $\rightarrow$ demonstrates a low-risk control case. These headers are not independently re-verified by the agent.

### Step 3: Run the Investigation
- Click the large cyan button: **"Run AI Forensic Investigation"**.
- Watch the **Animated DAG Canvas** dynamically populate nodes:
  - `User Request` $\rightarrow$ `Agent Planner` $\rightarrow$ `EmailForensicsTool` $\rightarrow$ `URLForensicsTool` $\rightarrow$ `ReputationEnrichmentTool` $\rightarrow$ `Evidence Correlation` $\rightarrow$ `Risk Assessment` $\rightarrow$ `Actionable Playbook`.
- Inspect the **Agent Decision Trace**: Read the transparent rationale for every tool selected.
- Review **Cross-Source Correlations**: See how individual clues form a high-confidence threat narrative.
- Inspect the **Containment Playbook**: Review proposed response actions and use the approval flow to demonstrate human sign-off. Validate any execution integration in a safe test environment.
- Click **"Export Forensic Dossier"** to open an executive, printable PDF/HTML investigation report.

---

## 14. Prototype Validation

The local validation scripts exercise the core agent workflow and API without requiring a live web server:

```powershell
python test_agent.py
python test_agent_api.py
```

**Most recent local check:** Both scripts passed on 2026-10-01 with Python 3.14.5. The agent checks covered a phishing email with an automatically discovered URL, a direct suspicious URL, a legitimate email control, and browser-history triage. The API checks covered preset scenarios, URL and email investigations, dynamic URL follow-up, investigation retrieval, HTML report generation, and an empty-payload `400` response.

These checks establish that the tested local paths ran successfully; they do **not** establish production readiness, calibrated accuracy, 500–1,000-case daily throughput, performance under concurrent load, or end-to-end resolution times. External reputation results depend on configuration and service availability; without credentials, some integrations can return mock or unavailable results. Before a bank or government pilot, add a representative labeled evaluation set, measure precision/recall and false negatives, run load and failure-mode tests, and validate deployment security controls.

---

## 15. Measurable Operational Impact

The following are planning targets and workflow comparisons, not independently validated production results. A bank pilot should measure end-to-end performance on representative Indian banking evidence and report automated processing separately from analyst review and remediation.

| Metric | Manual investigation baseline | FEIA planning target | Interpretation |
| :--- | :--- | :--- | :--- |
| **Automated triage processing time** | 25–45 minutes manual handling (scenario baseline) | 1.8–3.2 seconds (target) | Approximately 99.8–99.9% less processing time in a bounded comparison; not end-to-end resolution time |
| **Indicator extraction** | Manual and analyst-dependent | Automated for supported evidence | Validate omissions and extraction quality on a labeled dataset |
| **Cross-source link pivoting** | Manual URL extraction and lookup | Autonomous follow-up for discovered links | Reduces manual handoffs; does not guarantee no missed leads |
| **Playbook preparation** | Manual case documentation | Structured recommendations | Actions remain subject to authorized human approval |
| **Investigation record** | Analyst notes and separate tool outputs | Structured JSON state and report | Supports review; not by itself immutable or court-ready evidence |

---

## 16. Responsible AI, Security & Human-in-the-Loop Policies

FEIA is intended to support responsible, human-supervised investigation. Deploying organizations remain responsible for validating the system, evidence-handling process, and applicable policy:

1. **Human-in-the-Loop (HITL) Enforcement**:
   - The agent **never executes destructive or perimeter actions autonomously** (such as dropping network routes, modifying production firewalls, or revoking accounts).
   - All containment steps are marked as **Recommendations** requiring explicit analyst authorization. Any `HIGH` or `CRITICAL` finding displays a mandatory `HUMAN REVIEW REQUIRED` gate.
2. **Preservation of Uncertainty**:
   - Reports should separate **observed evidence** (e.g., an SPF failure stated in supplied authentication headers) from **probabilistic model output** (e.g., a phishing score). A domain-registration age should only be reported if an actual lookup supplies it.
   - Scores are decision-support signals; validate model calibration, error rates, and limitations on representative data.
3. **No Evidence Fabrication / Anti-Hallucination**:
   - Forensic indicators are extracted directly from verifiable byte streams and RFC specifications. The agent never invents indicators, domains, or network hops.
4. **Credential & Privacy Protection**:
   - No external API keys (e.g., VirusTotal) are exposed in the frontend or hardcoded into source files. All secrets are read via server-side environment variables (`os.environ.get('VT_API_KEY')`).
   - Browser-history evidence is sensitive. Review data flows and external reputation lookups before deployment; only submit indicators that the organization's policy permits.
5. **Full Auditability**:
   - Investigations receive identifiers and structured action traces. Protect and retain those records using access controls, retention policies, and tamper-evident logging appropriate to the organization's evidence-handling requirements; the application log alone is not an immutable chain of custody.

---

## 17. Repository Structure

```
new-agent-forensic/
├── Dockerfile                   # Multi-stage production container definition
├── docker-compose.yml           # Single-command container deployment
├── .dockerignore                # Container build exclusion list
├── requirements.txt             # Python dependencies
├── README.md                    # Comprehensive technical documentation
├── app.py                       # Flask API, SocketIO, and investigation endpoints
├── agent_core.py                # Planner, forensic tools, correlation, and risk
├── feature_extractor.py         # URL and email feature extraction
├── email_parser.py              # RFC 822 email parser
├── history_parser.py            # Browser-history SQLite parser
├── integrations.py              # External reputation integrations
├── models/                      # Configured phishing-classification models
├── sample_emails/               # Demonstration and test email artifacts
├── static/                      # Workbench styles and browser scripts
├── templates/                   # FEIA investigation workbench
├── docs/                        # Documentation index
├── PROBLEM_STATEMENT.md         # Bharat-specific problem framing
├── WORKFLOW.md                  # Investigation workflow guide
└── BANK_ROI_CASE_STUDY.md       # Illustrative Indian bank ROI case study
```

---

## 18. Platform Architecture & Standards

- **System**: Forensic Evidence Intelligence Agent (FEIA)
- **Context**: Digital forensics and cyber incident triage for Indian banks, fintechs, government IT, and SMEs
- **Core Technologies**: Python, Flask, SocketIO, Scikit-Learn, SHAP, Docker, TailwindCSS, Chart.js

*FEIA aims to strengthen India's digital resilience by helping investigators move from scattered evidence to a timely, reviewable decision—while keeping people accountable for consequential actions.*

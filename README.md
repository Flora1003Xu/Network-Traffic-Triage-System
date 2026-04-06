# LLM-Assisted SOC Triage & Reporting System

> An automated alert triage pipeline for Security Operations Centers (SOCs) that uses large language models to classify network intrusion alerts, reduce false positives, and generate structured incident reports.

---

## Overview

Modern SOC teams are overwhelmed by high volumes of IDS alerts from tools like Zeek and Suricata. Analysts manually triage thousands of alerts daily, many of which are false positives, leading to alert fatigue and delayed response to real threats.

This project builds a two-layer LLM-assisted triage pipeline that:

1. Ingests raw Zeek and Suricata logs
2. Runs two specialized triage agents in parallel to classify each source independently
3. Filters out benign traffic using a confidence threshold
4. Escalates suspicious/malicious findings to a central analyst agent for cross-source correlation
5. Generates a structured incident report saved to disk

---

## Architecture

```
Webhook (POST /soc-triage)
        │
        ▼
  Split Logs (Code)
   ┌────┴────┐
   │         │
   ▼         ▼
Zeek      Suricata
Triage    Triage
Agent     Agent
(Gemini)  (Gemini)
   │         │
   └────┬────┘
        ▼
  Parse + Merge
  (confidence threshold)
        │
        ▼
       IF ──── benign ──► discard
        │
        ▼ suspicious / malicious
  Central Analyst Agent
  (Gemini — cross-source correlation)
        │
        ▼
  Incident Report
  (structured JSON + saved to disk)
```

Each triage agent independently classifies its source as `benign`, `suspicious`, or `malicious` with a confidence score. The confidence threshold node prevents low-confidence verdicts from escalating. The central agent correlates findings from both sources to produce a final severity assessment and traceable evidence chain.

---

## Evaluation Results

Tested against **100 labelled test cases** across **16 attack categories**.

| Metric | Score |
|--------|-------|
| Verdict accuracy (malicious/benign) | **100%** (100/100) |
| False positive rate | **0%** |
| False negative rate | **0%** |
| Severity exact match | **53%** |
| Severity within ±1 level | **91%** |
| Severity within ±2 levels | **100%** |

### Attack categories covered

| Category | Cases | Category | Cases |
|---|---|---|---|
| C2 Beacon | 5 | SQL Injection | 5 |
| Port Scan | 5 | XSS Injection | 5 |
| Data Exfiltration | 10 | CC Attack | 5 |
| Brute Force SSH | 5 | DDoS | 5 |
| DNS Tunneling | 5 | Malware C2 Callback | 5 |
| Lateral Movement | 7 | Brute Force | 5 |
| Privilege Escalation | 7 | Web Shell | 7 |
| Reconnaissance | 14 | Normal Traffic | 5 |

### Key finding

The LLM pipeline shows a consistent **conservative bias** — it tends to over-report severity rather than under-report. In a SOC context this is the preferred failure mode: better to over-triage than to miss a real incident. The 91% severity ±1 accuracy compares favourably to reported inter-analyst agreement rates of 70–80% in operational SOC studies.

---

## Tech Stack

- **n8n** — workflow orchestration (self-hosted via Docker)
- **Google Gemini Flash** — LLM backbone for all three agents
- **Zeek** — network traffic analysis logs
- **Suricata** — IDS alert logs
- **Python** — evaluation scripts

---

## Repository Structure

```
NEtwork-Traffic-Triage-System/
├── README.md
├── n8n/
│   └── workflow_export.json        # n8n workflow (import directly into n8n)
├── evaluation/
│   ├── test_cases_100.json         # 100 labelled test cases
│   ├── run_evaluation.py           # automated evaluation script
│   └── analyze_severity.py        # severity ±1 analysis script
└── docs/
    └── progress_update_II.pptx     # progress presentation slides
```

---

## Getting Started

### Prerequisites

- Docker and Docker Compose
- n8n (self-hosted)
- Google Gemini API key

### 1. Start n8n

```bash
docker-compose up -d
```

Your `docker-compose.yml` should include:

```yaml
services:
  n8n:
    image: n8nio/n8n
    ports:
      - "5678:5678"
    environment:
      - NODE_FUNCTION_ALLOW_BUILTIN=fs,path
    volumes:
      - ~/.n8n:/home/node/.n8n
      - ~/n8n-reports:/home/node/reports
```

### 2. Import the workflow

1. Open n8n at `http://localhost:5678`
2. Go to **Workflows** → **Import from file**
3. Select `n8n/workflow_export.json`
4. Add your Google Gemini API credential under **Credentials**
5. Click **Publish** to activate

### 3. Run evaluation

```bash
pip3 install requests
cd evaluation/
python3 run_evaluation.py
python3 analyze_severity.py
```

The evaluation script sends each test case to the webhook and scores the pipeline's verdict and severity against the ground truth labels.

### 4. Manual testing

Send a log payload directly to the webhook:

```bash
curl -X POST http://localhost:5678/webhook/soc-triage \
  -H "Content-Type: application/json" \
  -d '{
    "chatInput": "{\"zeek\": \"<zeek log here>\", \"suricata\": \"<suricata alert here>\"}"
  }'
```

Incident reports are automatically saved to `~/n8n-reports/`.

---

## Sample Incident Report Output

```
🚨 INCIDENT REPORT — INC-2026-04-05T22:21:24Z
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : Critical
Verdict  : malicious
Confidence: 97%

📋 Summary
A host at 192.168.1.105 is beaconing to known CobaltStrike C2
infrastructure at 185.220.101.45 at precise 60-second intervals.
Both Zeek and Suricata independently confirm the pattern. Immediate
isolation of the affected host is recommended.

🔍 Indicators of Compromise
• 185.220.101.45:80 — known C2 IP
• Beacon interval: 60.0s ±0.5s (highly regular)
• ET MALWARE Win32/CobaltStrike Beacon (Suricata rule 2025901)
• JA3 fingerprint matches known Cobalt Strike profile

✅ Recommended Actions
• Isolate 192.168.1.105 from network immediately
• Capture full memory dump for forensic analysis
• Review all outbound connections from this host in past 72h
• Check for lateral movement to adjacent hosts
```

---

## Project Context

This project was developed as part of a university security course. The goal is to demonstrate that LLM-based reasoning can meaningfully reduce SOC alert fatigue while maintaining high detection accuracy.

**Limitations:**
- Evaluated on synthetic log data; real-world performance may vary
- Severity calibration requires tuning to organisational risk thresholds
- No live Wazuh integration in current prototype (planned extension)

---

## License

MIT

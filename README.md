# SentiHealth

**Autonomous, zero-cloud healthcare cybersecurity — ML-driven threat detection with self-healing and human-in-the-loop authorization.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Dashboard-Flask-lightgrey?logo=flask)
![React](https://img.shields.io/badge/Frontend-React%20%2F%20Vite-61DAFB?logo=react&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-green)

SentiHealth monitors a live hospital EHR web server, scores every network event using a 5-model ML ensemble in real time, and automatically executes tiered self-healing responses — from IP throttling to full database snapshots — with cryptographic audit logging and admin MFA approval for high-risk actions.

> **RV College of Engineering — Experiential Learning Project 2024-25 · Team 57 · Theme: SDG**

---

## Table of Contents

1. [Problem and Goals](#problem-and-goals)
2. [How It Works](#how-it-works)
3. [ML Ensemble Details](#ml-ensemble-details)
4. [Security Architecture](#security-architecture)
5. [Repository Layout](#repository-layout)
6. [Quickstart](#quickstart)
7. [Technologies Used](#technologies-used)
8. [Limitations and Future Work](#limitations-and-future-work)

---

## Problem and Goals

**Problem:** Hospitals are the #1 target for ransomware and data exfiltration. Existing ML-based security tools either depend on cloud infrastructure (violating HIPAA air-gap requirements) or require constant manual human review — making them too slow for millisecond-scale intrusions.

**Goals:**
- **Detect threats in real time** from live network event logs, with 100% zero-cloud on-premises operation.
- **Automate tiered responses** (throttle, lockout, snapshot) proportional to threat severity.
- **Keep humans in the loop** — High-tier threats require TOTP MFA-authenticated admin approval before action.
- **Deliver zero-cloud alerting** — Real-time LAN desktop notifications via `local_notifier_client.py` consuming SSE (`/api/stream`).
- **Leave a tamper-proof audit trail** — Write-ahead dual-replicated SHA-256 hash-chained ledger (`audit_chain.json` & `audit_chain_replica.json`).
- **Continuously improve** via a human-in-the-loop retraining queue: confirmed attacks feed directly back into the ML pipeline.

---

## How It Works

### Plain-Language Flow

1. A **Node.js EHR server** generates live network event logs (`events.jsonl`) simulating hospital web traffic.
2. **`core/live_sentinel.py`** tails the log stream in real time; `ml/features.py` turns each user/IP's recent history into windowed features (5-minute and 1-hour counts, deviation from the entity's own 24-hour baseline, shift and time context).
3. The **detection models** score each event and assign a **Threat Tier** — Low, Medium, or High: a calibrated XGBoost for known attack patterns, an Isolation Forest for activity that is unusual for that user/IP, and a small, documented rule layer. The event's own `attack_type` label is never used for the decision.
4. The **Self-Healing Responder** executes the appropriate automated action based on tier.
5. **High-tier events** trigger immediate **SSE desktop alerts** (`local_notifier_client.py`) and dashboard challenges requiring TOTP MFA-verified admin approval before high-risk execution.
6. Every action is appended to a **write-ahead dual-replicated audit ledger** — entries cannot be silently deleted or tampered with without triggering `HALTED_CORRUPTION`.
7. Admins can flag misclassified events via a **review queue**, which feeds confirmed attacks back into the retraining pipeline to continuously improve model accuracy.

### Architecture Diagram

```mermaid
flowchart LR
  subgraph source [EHR Server]
    N[Node.js webapp] -->|events.jsonl| LOG[Live Log Stream]
  end

  subgraph sentinel [Live Sentinel AI]
    LOG --> FE[Feature Engineering\n8 features per event]
    FE --> ENS[5-Model ML Ensemble\nRF · XGB · GBM · SVM · LR]
    ENS --> TIER[Threat Tier\nLow / Medium / High]
  end

  subgraph response [Self-Healing Responder]
    TIER -->|Low| AUTO1[Log & Monitor]
    TIER -->|Medium| AUTO2[IP Throttle\nAccount Lockout]
    TIER -->|High| APPR[Admin MFA Approval]
    APPR -->|Approved| AUTO3[Database Snapshot\nFull Lockdown]
  end

  subgraph audit [Audit and Retraining]
    AUTO1 & AUTO2 & AUTO3 --> CHAIN[SHA-256 Hash-Chained\nAudit Ledger]
    CHAIN --> RQ[Review Queue]
    RQ --> RETRAIN[Human-in-the-Loop\nModel Retraining]
  end
```

### The Four Layers

| Layer | Component | What It Does |
|-------|-----------|--------------|
| **1 — Target** | Node.js EHR Server | Generates live network event logs simulating hospital web traffic |
| **2 — Watchdog** | `core/live_sentinel.py` + `ml/features.py` | Tails logs, builds windowed per-entity features, feeds events to the models |
| **3 — Brain** | `ml/scoring_matrix.py` | Calibrated XGBoost + Isolation Forest + rule layer; cost-based tier decision with a per-event explanation |
| **4 — Responder** | `self_healing_responder.py` | Executes automated responses and manages admin approval for High-tier events |

---

## Detection Models

> All numbers in this section are measured on **synthetic data** (`ml/simulate_events.py`). They show that the pipeline works, not how it performs on a real hospital. See `evaluation/REPORT.md` for the full, regenerated report.

### Data

No public dataset of hospital EHR access logs with labelled attacks exists, so `ml/simulate_events.py` generates minute-level activity for 120 users over 14 days: normal behaviour driven by role and shift (including remote and on-call sessions), with ten attack families overlaid as campaigns. Labels come from the campaign, never from thresholds on the features. Stealthy variants are included on purpose: low-and-slow brute force (2–4 failures a minute for hours), slow exfiltration that stays under 500 KB/h, and off-hours insider access. One family (`credential_stuffing`) is held out of training to measure detection of an attack type the models never saw. The generator is deterministic; the dataset is 334,531 minute-records, 1.3 % of them attack traffic.

### Features (`ml/features.py`)

Each record is scored with 29 features computed from that user/IP's own history: counts and ratios over the last **5 minutes** and **1 hour** (logins, failures, failure ratio, EHR reads, export KB, requests, distinct endpoints, internal hosts, CPU, memory), the entity's **24-hour baseline** and the current hour's deviation from it, and context (hour of day, weekend, off-shift score from the roster, IP reputation). The same code runs in batch for training and incrementally in the live sentinel; a test checks that the two agree. The eight legacy feature names (`failed_logins`, `cpu_usage`, …) are derived from these for the rule layer and the dashboard.

### Models (`ml/train.py`, `ml/scoring_matrix.py`)

| Component | Role |
|-----------|------|
| **XGBoost, isotonic-calibrated** | Supervised Low/Medium/High classifier; configuration chosen on the validation period, calibrated on it |
| **Isolation Forest** (normal rows only) | Unsupervised path for attacks the classifier never saw; raises Low to Medium when a stream record is unusual for that entity |
| **Cost policy** (`ml/cost_matrix.py`) | The tier with the lowest expected cost, instead of a plain argmax |
| **Rule layer** (`ml/rules.py`) | The deployed failed-login thresholds, kept separate so they can be switched off (`SENTIHEALTH_RULES=0`) and evaluated alone |
| **Context** (`core/context.py`) | On-shift + badge, emergency or registered proxy lower an uncertain tier by one; roster-but-external raises it |

Training uses a **temporal split** (first 70 % of the period to train, next 15 % to select and calibrate, last 15 % to test). The previous five-model ensemble (RF, GB, SVM, LR, XGB) is still trained with `--legacy` so the ablation can be reproduced.

### Measured results (test period, 50,130 rows, 562 of them attacks)

| System | Macro F1 | High recall | High precision | False alarms on normal |
|---|---|---|---|---|
| XGBoost (calibrated) | 0.974 | 0.997 | 0.981 | 0.09 % |
| Random Forest (single, calibrated) | 0.972 | 1.000 | 0.981 | — |
| Legacy 5-model ensemble | 0.958 | 0.994 | 0.983 | — |
| Expert rules only | 0.556 | 0.997 | 0.616 | 21 % |
| Deployed rules only (failed logins) | 0.651 | 0.164 | 0.935 | — |

Every attack campaign in the test period is detected (row-level detection ≥ 0.89 for all families except reconnaissance, which is Low-tier by definition). On the held-out family, XGBoost flags 36 % of rows but all campaigns; the Isolation Forest flags 100 % of rows at 2.5 % false alarms. A single calibrated model matches or beats the five-model ensemble at 25× lower latency, which is why the live path uses one model.

### Safeguards

- **No label leak** — the event's `attack_type` field is metadata only; `tests/test_ml_pipeline.py` checks it cannot move the tier.
- **Deterministic scoring** — the same input always gives the same score; nothing is randomised.
- **Poisoning check on retraining** — `core/review_queue.py` flags approvals that would shift the approved-per-tier distribution suspiciously.
- **SHA-256 model manifest** — each saved model file is checksummed; a swapped model file stops the sentinel on load.

---

## Security Architecture

```
[Node.js EHR] → [events.jsonl] → [live_sentinel.py]
    → [Feature Engineering (8 features)]
    → [ML Ensemble: RF + XGB + GBM + SVM + LR]
    → [Threat Tier: Low / Medium / High]
    → [Self-Healing Responder]
        ├── Low:    Log & continue
        ├── Medium: IP throttle + account lockout
        └── High:   MFA-gated admin approval → DB snapshot + lockdown
    → [SHA-256 Hash-Chained Audit Ledger]
    → [Review Queue → Human-in-the-Loop Retraining]
```

**Cryptographic Audit Ledger:** Every response action is appended as a hash-chained JSON entry. Each entry includes the SHA-256 hash of the previous entry, making silent log deletion or tampering cryptographically detectable — the same principle used in blockchain consensus.

**SHAP Explainability:** Every High-tier alert includes a SHAP waterfall chart explaining *which features* drove the ensemble's decision, ensuring admins can make informed approval decisions rather than blindly trusting a black-box score.

**Deception Layer:** `deception/` implements a Mirage honeypot that injects fake-but-convincing EHR data into attacker sessions, records flagged sessions for retraining, and applies noise to confuse reconnaissance tools — all without disrupting legitimate traffic.

**Privacy Controls:** `privacy/` provides HIPAA-aligned pseudonymisation (`pseudonymize.py`) and cryptographic data shredding (`crypto_shred.py`) — patient identifiers can be irreversibly purged by destroying the encryption key alone.

---

## Repository Layout

```
unisyshealth/
├── webapp/                  # Node.js EHR server (attack target, port 3000)
├── frontend/                # React/Vite/TypeScript admin dashboard UI
├── deception/               # Mirage honeypot & deception layer
├── notifications/           # Alert dispatch — Telegram, console, dual-notifier, SMTP
├── privacy/                 # HIPAA-aligned pseudonymisation and crypto-shredding
├── attack_scripts/          # Cyberattack simulators (exfiltration, brute-force, port scan)
├── config/                  # Runtime config: thresholds, notifier, deception policy, TLS certs
├── data/                    # Synthetic EHR dataset, audit chain, user DB
├── models/                  # Serialized calibrated model files + SHA-256 manifest
├── evaluation/              # Model evaluation scripts and metrics
├── demos/                   # Standalone demo scripts (crypto-shred, pseudonymize, scenario)
├── scripts/                 # Operational scripts + shell launchers
│   ├── setup.sh             # One-time environment setup
│   ├── reset_and_run.sh     # Pre-demo reset & pre-flight checklist
│   ├── health_monitor.py    # System health daemon (runs as systemd service)
│   ├── backup_db.py         # Manual DB backup utility
│   └── ...                  # Emergency unblock, restore, TLS cert generation, etc.
├── tests/                   # Pytest suite (sentinel, tiers, MFA, rate-limit, DB backup)
├── docs/                    # All project documentation
│   ├── AGENTS.md            # Agent onboarding instructions (read this first)
│   ├── CONTRIBUTING.md      # Contributor guide
│   ├── DISASTER_RECOVERY.md # Operational disaster-recovery runbook
│   ├── FUTURE_WORK.md       # Known limitations and planned enhancements
│   ├── MODEL_METRICS.md     # Ensemble performance metrics and evaluation methodology
│   ├── DECISION_RECORD.md   # Architecture decision log
│   ├── constitution.md      # Project constitution and design principles
│   ├── trd.md               # Technical requirements document
│   └── ...                  # Additional design and demo docs
├── api/dashboard.py         # Real-time Flask dashboard backend (port 5001)
├── core/                    # live_sentinel.py, self_healing_responder.py, review_queue.py,
│                            # context.py, local_notifier_client.py
├── ml/                      # model_trainer.py, scoring_matrix.py, data_generator.py
├── security/                # database.py (SQLite / PostgreSQL), secrets_vault.py
├── _paths.py                # Single source of truth for all filesystem paths
├── requirements.txt
└── LICENSE
```

---

## Quickstart

### Prerequisites

- Python 3.10+
- Node.js 18+
- *(Optional)* PostgreSQL — if omitted, SentiHealth auto-initializes a local SQLite DB at `data/app.db`

### 1. Environment Setup

```bash
bash scripts/setup.sh
source .venv/bin/activate
```

*(Optional — PostgreSQL only)*
```bash
export DATABASE_URL="postgresql://sentiuser:sentipass@localhost:5432/sentihealth_db"
```

### 2. Train the ML Models

Only needed on first run or after dataset changes:

```bash
python3 ml/model_trainer.py
```

### 3. Start the System

Open **6 separate terminal windows** and run in order:

**Terminal 1 — Database & EHR Web App**
```bash
source .venv/bin/activate
python3 security/database.py   # Initialize schema and tables
cd webapp && node app.js       # EHR web app on port 3000
```

**Terminal 2 — Flask Dashboard Backend**
```bash
source .venv/bin/activate
python3 api/dashboard.py       # Admin dashboard on http://localhost:5001
```
> **First-time setup:** On first start the backend creates `data/users.json`, `config/.secrets_vault.json` and the admin account, and prints the admin's TOTP secret and 8 backup codes in this terminal. Log in with `admin` / `adminpass123`, change the password, add the TOTP secret to Google Authenticator or Authy, and save the backup codes. These files hold secrets and are git-ignored: never commit them.

**Terminal 3 — Local Desktop Alert Client**
```bash
source .venv/bin/activate
python3 core/local_notifier_client.py   # Receives High-tier alerts via SSE (/api/stream)
```

**Terminal 4 — Live Sentinel AI Engine**
```bash
source .venv/bin/activate
python3 core/live_sentinel.py  # Tails event logs, scores with 5-model ensemble
```

**Terminal 5 — React Frontend UI** *(optional)*
```bash
cd frontend
npm install
npm run dev                    # Vite dev server (URL shown in terminal)
```

**Terminal 6 — Attack Simulation** *(validation)*
```bash
source .venv/bin/activate
python3 attack_scripts/exfiltration.py
```

Watch the sentinel detect, classify, and respond to the live attack in real time on the dashboard.

### Pre-Demo Reset

To reset all state before a demo session:
```bash
bash scripts/reset_and_run.sh
```
This runs a pre-flight checklist (Python version, Node.js, `.env`, virtual env, model files) and clears ephemeral state.

### Deploying the frontend on Vercel

The Vercel site is only the frontend. The Flask backend still runs on your machine and is reached through a tunnel:

1. Create a free ngrok account, then `export NGROK_AUTHTOKEN=...` and (recommended) `export NGROK_DOMAIN=<your free static domain>.ngrok-free.app`.
2. Start the backend: `python3 api/dashboard.py`. It prints the public backend URL.
3. In the Vercel project (Root Directory: `frontend`), set the environment variable `VITE_API_BASE_URL` to that URL and redeploy.

If the backend is not running, the login page says the server is unreachable and offers a clearly labelled demo with simulated data. Nobody can log in without the backend.

---

## Technologies Used

| Component | Technology |
|-----------|------------|
| Core Sentinel | Python 3.10+ |
| ML Models | scikit-learn, XGBoost |
| Model Calibration | `CalibratedClassifierCV` (isotonic, 5-fold CV) |
| Class Imbalance | SMOTE (imbalanced-learn) |
| Explainability | SHAP, Matplotlib |
| EHR Target Server | Node.js, Express |
| Live Dashboard (backend) | Flask, Plotly |
| Frontend UI | React, Vite, TypeScript |
| Admin Notifications | Telegram Bot API, SMTP, console |
| Cryptography | SHA-256 HMAC (hash-chained audit ledger) |
| Privacy | Pseudonymisation, Crypto-shredding (AES-256) |
| MFA | TOTP via `pyotp` (RFC 6238) |

---

## Limitations and Future Work

| # | Limitation | Planned Enhancement |
|---|-----------|---------------------|
| 1 | Audit ledger on a single node (deletable by root attacker) | Migrate to **Hyperledger Fabric** distributed ledger |
| 2 | IP spoofing dilutes per-IP velocity metrics | IPv6 + MAC cross-referencing, session token fingerprinting |
| 3 | Telegram alerts require external internet (violates air-gap) | On-premises SMS gateway or hospital pager system (Spok) |
| 4 | Models learn only from local hospital attacks | **Federated Learning** for cross-hospital weight sharing (HIPAA-compliant) |
| 5 | Mock Node.js server, not a real EHR | **HL7 FHIR** integration (Epic, Cerner) |
| 6 | Review queue vulnerable to admin-level model poisoning | Adversarial robustness checks in retraining pipeline |
| 7 | All detection results are on synthetic data written by the same author as the features | Evaluate on a public benchmark (CIC-IDS2017 / UNSW-NB15 for the network part) and on real, de-identified access logs |
| 8 | Live events from the web app arrive as 60-second snapshots, so the 1-hour and 24-hour baseline features are only approximated | Send raw per-minute counts to the sentinel and let `ml/features.py` keep the history |

See [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md) for detailed discussion of each limitation.

---

## License

MIT — see [`LICENSE`](LICENSE).

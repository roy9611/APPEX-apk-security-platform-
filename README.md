# AppEX — Android Application Exposure Engine

> Static analysis infrastructure for Android APKs. Drop a binary, get a complete threat profile in under 60 seconds.

---

## What This Is

AppEX is a full-stack static analysis platform purpose-built for Android APK security assessment. It chains together industry-standard reverse engineering tools — apktool, jadx — with a custom multi-module detection engine and a Groq-powered AI layer that translates raw findings into actionable intelligence.

No manual manifest inspection. No grepping through decompiled Java by hand. No context-switching between 6 different tools. One interface, one report.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AppEX v1.0.0                            │
├─────────────────────────────────────────────────────────────────┤
│  React 18 + Vite                    Terminal Dashboard UI        │
│  ├── Upload & live scan progress                                 │
│  ├── Per-module findings with severity breakdown                 │
│  ├── Risk score gauge (0–100, weighted)                          │
│  └── AI analyst chat (contextual, scan-aware)                   │
├─────────────────────────────────────────────────────────────────┤
│  FastAPI (Python 3.14)              Analysis Backend             │
│  ├── /api/scan      POST  — receive APK, queue background scan   │
│  ├── /api/scan/{id} GET   — live status polling                  │
│  ├── /api/report    GET   — full serialized ScanResult           │
│  ├── /api/chat      POST  — contextual AI queries on findings    │
│  └── /api/health    GET   — liveness probe                       │
├─────────────────────────────────────────────────────────────────┤
│  Detection Engine               8 Analysis Modules               │
│  ├── manifest_analyzer    — exported components, debug flags     │
│  ├── permission_analyzer  — dangerous permission combinations    │
│  ├── secret_scanner       — 12 regex patterns + entropy check    │
│  ├── firebase_checker     — live DB exposure probe               │
│  ├── ssl_checker          — TrustManager bypass, NSC misconfig   │
│  ├── storage_analyzer     — world-readable files, unencrypted DB │
│  ├── yara_scanner         — 32 compiled rules across 5 rulesets  │
│  └── report_engine        — smart weighted scoring (0–100)       │
├─────────────────────────────────────────────────────────────────┤
│  AI Layer                       Groq (llama-3.3-70b-versatile)   │
│  ├── summarizer   — executive risk summary from findings JSON    │
│  ├── explainer    — per-finding impact + remediation guidance    │
│  └── chat         — scan-context-aware interactive analyst       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Coverage

| Module | What It Catches | Max Severity |
|---|---|---|
| Manifest Analyzer | Debuggable flag, allowBackup, exported components without permissions, cleartext traffic | CRITICAL |
| Permission Analyzer | Dangerous permission combos (READ_SMS+INTERNET, RECORD_AUDIO+INTERNET, etc.) | HIGH |
| Secret Scanner | AWS keys, GCP tokens, Stripe live keys, JWT secrets, private key blocks, Slack/GitHub tokens | CRITICAL |
| Firebase Checker | Open Realtime Database — live HTTP probe, not just config presence | CRITICAL |
| SSL Checker | Empty `checkServerTrusted`, `HostnameVerifier` returning `true`, missing cert pinning | CRITICAL |
| Storage Analyzer | `MODE_WORLD_READABLE/WRITEABLE`, external storage misuse, unencrypted SQLite | HIGH |
| YARA Scanner | 32 rules: malware patterns, SMS exfiltration, accessibility service abuse, obfuscation indicators | CRITICAL |

**Risk scoring** is not a simple finding count. Each finding class carries a weight multiplier. YARA detections score 1.5×, confirmed credential exposure scores 2.0×, entropy noise scores 0.1×. Per-module caps prevent a single noisy module from dominating the total. Score normalizes to 0–100.

---

## Setup

### Prerequisites

```bash
# System dependencies
sudo apt install apktool jadx   # Debian/Ubuntu
sudo dnf install apktool jadx   # Fedora

# For YARA scanner (compile from source on Python 3.12+)
sudo apt install gcc python3-dev yara-dev   # Debian
sudo dnf install gcc python3-devel yara-devel   # Fedora
```

### Backend

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Set GROQ_API_KEY in .env

# Run
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.14, FastAPI, uvicorn |
| AI | Groq API, llama-3.3-70b-versatile |
| Decompilation | apktool 2.x, jadx 1.x |
| Pattern matching | YARA 4.5, custom rulesets |
| Frontend | React 18, Vite 5 |
| Fonts | JetBrains Mono |

---

## Changelog

### v1.0.0 — Initial Release
- Full-stack APK static analysis platform
- 6 core detection modules (manifest, permissions, secrets, firebase, ssl, storage)
- FastAPI backend with async scan pipeline
- React terminal dashboard with live progress tracking
- Groq AI integration: summary, per-finding explanation, interactive chat

### v1.1.0 — YARA Engine + Smart Scoring
- Added YARA scanner module with 32 compiled rules across 5 rulesets (manifest, secrets, network, storage, malware)
- Rewrote risk scoring engine with per-module weight caps, finding-type multipliers, and context bonuses
- Entropy-noise suppression (0.1× multiplier on high-entropy near-miss detections)
- YARA deduplication by (rule, file stem) with credential rules always fully reported

### v1.2.0 — UI Overhaul: AppEX Terminal Aesthetic
- Complete frontend redesign — replaced card-based layout with dense terminal dashboard
- New component architecture: TitleBar, SectionBar, StatusBar, LeftSidebar, RightPanel
- JetBrains Mono throughout, terminal green (#00ff88) accent system
- AI analyst panel with boot sequence, suggestion chips, contextual chat
- Collapsible chart sections, animated risk score counter, scan progress timeline
- Project renamed from APPCHECK to AppEX

---

## License

MIT. Use it, fork it, break things with it — responsibly.

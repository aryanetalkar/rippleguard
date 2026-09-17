# RippleGuard

> AI-Powered Open-Source Software Supply-Chain Risk Intelligence Platform

---

## 1. Project Overview & Problem Statement

Modern software applications rely on intricate, deep dependency trees. Today, security teams face massive alert fatigue:
- Vulnerability scanners generate hundreds of raw CVEs sorted solely by **CVSS base scores**.
- A CVSS 9.8 vulnerability in an isolated leaf package with zero downstream leverage often obscures a CVSS 7.5 vulnerability in a high-centrality shared package that directly reaches mission-critical applications.
- Existing tools lack **structural context**, **propagation simulation**, and **explainable mitigation prioritization**.

**RippleGuard** solves this by transforming static vulnerability lists into actionable structural risk intelligence through a unified 6-stage pipeline:

$$\textbf{Dependency Graph} \longrightarrow \textbf{Vulnerability Intelligence} \longrightarrow \textbf{Ripple Propagation} \longrightarrow \textbf{Structural Risk} \longrightarrow \textbf{Mitigation Priority} \longrightarrow \textbf{Explainable Evidence}$$

1. **Dependency Graph**: Ingests CycloneDX SBOMs, normalizes package identities via PackageURL (PURL), and constructs cycle-safe dependency graphs.
2. **Vulnerability Intelligence**: Fetches exact known vulnerabilities directly from the official OSV.dev open-source database.
3. **Ripple Propagation**: Deterministically traces compromise reachability from vulnerable seed packages upward through the dependency chain to root applications using the **Ripple Propagation Engine**.
4. **Structural Risk**: Computes a multi-factor mathematical structural risk score combining Severity, Subgraph Centrality, Blast Radius, and Application Criticality.
5. **Mitigation Priority**: Ranks actionable mitigations into deterministic priority bands (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNSCORED`).
6. **Explainable Evidence**: Synthesizes evidence-grounded AI narratives via Google Gemini (`gemini-3.8-flash`) rooted strictly in immutable deterministic evidence packs, ensuring AI is never the scoring authority.

---

## 2. Why RippleGuard is Different

| Feature | Conventional Scanners | RippleGuard |
| :--- | :--- | :--- |
| **Scoring Lens** | Isolated CVSS Base Score | 4-Factor Structural Risk (CVSS, Centrality, Blast Radius, Criticality) |
| **Reachability Simulation** | None (Static List) | Reverse BFS Ripple Propagation to Application Entrypoints |
| **Graph Modeling** | Flat tables or naive trees | NetworkX DiGraph + Cytoscape.js interactive topology |
| **AI Role** | Black-box scoring or ungrounded chat | Strictly Explanatory; Sovereign Deterministic Engine |
| **Hallucination Defense** | Vulnerable to prompt injection / hallucinations | Strict EvidencePack hashing, evidence ID whitelisting, certainty claim filtering |
| **Fail-Safe Operation** | Fails or halts on AI error | Graceful fallback: 100% deterministic analysis remains sovereign during AI outages |

---

## 3. Architecture & Data Flow

RippleGuard is implemented as a production-hardened **Modular Monolith**:

```text
       CycloneDX JSON SBOM
               │
               ▼
   [CycloneDX Parser & PURL Normalization]
               │
               ▼
     [Transactional Persistence] (PostgreSQL / SQLite)
          │               │
          ▼               ▼
   [OSV.dev Intelligence] [NetworkX Graph Engine]
          │               │
          └───────┬───────┘
                  ▼
      [Ripple Propagation Engine] (Reverse BFS Reachability)
                  │
                  ▼
      [Structural Risk Scoring & Mitigation Ranking]
                  │
          ┌───────┴───────┐
          ▼               ▼
 [Deterministic Results] [EvidencePack Snapshot & SHA-256]
          │               │
          │               ▼
          │         [Google Gemini Explanation Layer]
          │         (Pydantic Schema & Guardrails)
          │               │
          └───────┬───────┘
                  ▼
    [Next.js + Cytoscape.js UI Dashboard]
```

### Sovereign Deterministic Non-Negotiables:
1. **Deterministic Engine as Single Source of Truth**: Risk scores, priority ranks, bands, centrality, and blast radius are mathematically calculated and persisted before the AI layer is invoked.
2. **AI is Strictly Explanatory**: Gemini is prohibited from altering scores, ranks, bands, or inventing mitigation versions.
3. **Evidence-Only Grounding**: Explanations cite only defined, verified evidence IDs (`risk_score`, `priority_rank`, `cvss_score`, `centrality_score`, `affected_application_count`, etc.) drawn from canonical JSON snapshots.
4. **Prompt Injection Resistance — Tested**: Advisory texts are segregated as inert data inside `<evidence_data>` tags with explicit negative instructions.
5. **Deterministic Caching**: Explanations are cached against `(risk_result_id, evidence_hash, model_name, prompt_version)` to prevent duplicate API invocations.

---

## 4. Technology Stack

- **Backend**: FastAPI, Python 3.13+, Pydantic v2, SQLAlchemy 2.0, Alembic, HTTPX2, NetworkX 3.6.1, NumPy, SciPy, CVSS 3.6, google-genai 2.24.0.
- **Frontend**: Next.js 14 (App Router), TypeScript, Tailwind CSS, Cytoscape.js, Lucide React.
- **Database**: PostgreSQL / SQLite (via SQLAlchemy ORM & Core migrations).
- **Vulnerability Source**: OSV.dev REST API (`POST /v1/querybatch`, `GET /v1/vulns/{id}`).

---

## 5. Structural Risk Model & Priority Bands

### Mathematical Risk Formulation:
$$\text{Risk Score} = (w_{\text{sev}} \times \text{Severity}) + (w_{\text{cent}} \times \text{Centrality}) + (w_{\text{blast}} \times \text{Blast Radius}) + (w_{\text{crit}} \times \text{Criticality})$$

- **Default Configurable Weights**:
  - Severity Weight: **0.30** (30%)
  - Centrality Weight: **0.25** (25%)
  - Blast Radius Weight: **0.25** (25%)
  - Application Criticality Weight: **0.20** (20%)
  - Strict Validation: $\sum w = 1.00$.

### Priority Bands:
- `CRITICAL`: 75.00 – 100.00
- `HIGH`: 50.00 – 74.99
- `MODERATE`: 25.00 – 49.99
- `LOW`: 0.00 – 24.99
- `UNSCORED`: Missing CVSS base data (excluded from numerical ranking to prevent misrepresenting unknown severity as safe).

---

## 6. Supported Formats & Sources

- **SBOM Ingestion**: CycloneDX JSON specifications (versions 1.4, 1.5, 1.6). Maximum upload limit: 10 MB.
- **Vulnerability Intelligence**: OSV.dev Open Source Vulnerabilities database (Ecosystems: npm, PyPI, Maven, Go, Cargo, NuGet, Packagist, etc.).

---

## 7. Setup & Run Instructions

### Prerequisites
- Python 3.11+ (tested on Python 3.13)
- Node.js 18+ (tested on Node.js 20+)

### Environment Configuration
Copy `.env.example` to `backend/.env` (which is gitignored):
```bash
cp .env.example backend/.env
```
Populate `backend/.env` with your environment values:
```env
DATABASE_URL=sqlite:///./rippleguard.db
CORS_ORIGIN=http://localhost:3000
OSV_API_URL=https://api.osv.dev/v1
GEMINI_MODEL=gemini-3.8-flash
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

### 1. Run Backend Server
```bash
cd backend
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- Interactive API Docs: `http://localhost:8000/api/v1/docs`
- Health Check: `http://localhost:8000/api/v1/health`

### 2. Run Frontend Server
```bash
cd frontend
npm install
npm run dev
```
- Open `http://localhost:3000` in your browser.

---

## 8. Verification & Test Commands

### Backend Automated Test Suite
```bash
cd backend
.\.venv\Scripts\pytest -q
```
**Results**: `115 passed, 1 skipped in 3.50s` (100% core test suite passing).

### Frontend Production Build
```bash
cd frontend
npm run build
```
**Results**: Next.js compiled cleanly with 0 TypeScript/ESLint errors (4/4 static pages generated).

---

## 9. Demo Showcase Flow

Refer to [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the complete 11-step evaluation walkthrough:
1. Open RippleGuard (`http://localhost:3000`).
2. Ingest CycloneDX SBOM.
3. Explore Dependency Graph.
4. Scan OSV.dev Vulnerabilities.
5. Select a Vulnerable Seed Package.
6. Run Ripple Propagation Simulation.
7. Inspect Downstream Impact & Shortest Propagation Paths.
8. Calculate Structural Risk Score.
9. Review Ranked Mitigation Priorities.
10. Inspect "Why this rank?" breakdown.
11. Demonstrate AI Explanation & Fail-Safe Behavior.

---

## 10. Security Controls & Known Limitations

### Security Controls:
- **Zero Secrets**: No API keys, credentials, or tokens committed to source control; `.env` is gitignored; `.env.example` contains placeholders only.
- **Prompt Injection Resistance — Tested**: All untrusted external text is enclosed in `<evidence_data>` tags and filtered against certainty claims ("100% secure").
- **Strict Guardrails**: Output validated against Pydantic schema; citations validated against authorized evidence IDs; fabricated fixed versions rejected.
- **Resource Limits**: Max upload 10 MB, max ripple depth 10, max ripple nodes 500, max batch explanations 25.

### Known Limitations:
- **Upstream Gemini Availability & Graceful Failure**: The AI explanation layer features resilient, graceful failure handling. During final live verification, the upstream Google Gemini API encountered temporary high demand (`503 UNAVAILABLE`).
- **Deterministic Sovereignty Under AI Outages**: In the event of upstream Gemini unavailability, rate limits, or unconfigured API keys:
  - RippleGuard fails gracefully without application crashes or service degradation.
  - An informational fallback notice is rendered in the UI (*"AI explanation unavailable. Deterministic RippleGuard analysis is still available."*).
  - All deterministic risk scores, rankings, priority bands, and propagation metrics remain 100% sovereign, verified, and unchanged.

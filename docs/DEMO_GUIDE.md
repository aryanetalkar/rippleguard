# RippleGuard Demo Showcase Guide

A step-by-step walkthrough for evaluating and showcasing RippleGuard.

---

## Prerequisites
1. **Backend Server**: Running at `http://localhost:8000`
   ```bash
   cd backend
   .\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. **Frontend UI**: Running at `http://localhost:3000`
   ```bash
   cd frontend
   npm run dev
   ```

---

## Showcase Walkthrough (11 Steps)

### Step 1: Open RippleGuard
- Navigate browser to `http://localhost:3000`.
- Verify the header badge: **`RippleGuard Intelligence Monolith · Phase 6 Active`**.
- Notice the clean dashboard layout split into SBOM ingestion, Dependency Graph, Vulnerabilities, Ripple Engine, and Structural Risk Priority.

### Step 2: Ingest CycloneDX SBOM
- Under **Ingest CycloneDX SBOM**, click **Select CycloneDX JSON file**.
- Select a sample CycloneDX file (e.g. `backend/tests/fixtures/valid_minimal_cyclonedx.json`).
- Click **Upload & Parse**.
- Observe instantaneous normalization into canonical PURLs and transactional persistence.

### Step 3: Explore Dependency Graph
- View the interactive Cytoscape.js dependency graph canvas.
- Inspect application entrypoints and direct/transitive library dependencies.
- Use zoom and drag interactions to inspect node relationships (`source → target`).

### Step 4: Scan Vulnerabilities via OSV.dev
- Click **Scan OSV.dev Vulnerabilities**.
- RippleGuard queries the official OSV.dev API in paginated batches.
- Normalized CVE/GHSA advisories, CVSS vectors, and affected versions appear in the Vulnerabilities table.

### Step 5: Select a Vulnerable Seed Package
- In the Vulnerabilities or Graph table, locate a package with known vulnerabilities (e.g., `lodash@4.17.15`).
- Click **Simulate Ripple Impact** next to the selected package.

### Step 6: Run Ripple Propagation Simulation
- The deterministic Ripple Engine executes reverse breadth-first search (BFS) traversal across the dependency graph.
- Traces compromise reach from the vulnerable seed package upward to direct and transitive dependents and root applications.

### Step 7: Inspect Downstream Impact & Propagation Paths
- Examine the **Downstream Ripple Impact** card:
  - Total impacted node count.
  - Affected applications.
  - Shortest attack paths showing the exact chain of dependency leverage.

### Step 8: Calculate Structural Risk Score
- Navigate to the **Structural Risk & Mitigation Priority** section.
- Inspect the 4 configurable risk weights (Severity: 30%, Centrality: 25%, Blast Radius: 25%, Application Criticality: 20%).
- Click **Execute Risk Analysis**.
- The engine computes multi-factor mathematical scores combining CVSS severity, subgraph PageRank/Betweenness centrality, propagation reach, and application criticality tiers.

### Step 9: Review Ranked Mitigation Priorities
- View the **Prioritized Mitigation Queue** table.
- Vulnerabilities are deterministically grouped into priority bands:
  - `CRITICAL` (75.00–100.00)
  - `HIGH` (50.00–74.99)
  - `MODERATE` (25.00–49.99)
  - `LOW` (0.00–24.99)
  - `UNSCORED` (missing CVSS)
- Notice deterministic tie-breaking ensuring reproducible rankings.

### Step 10: Inspect "Why this rank?"
- Click **Inspect Risk Breakdown** on any ranked finding.
- The inspector modal displays the **Deterministic Analysis** (the immutable single source of truth):
  - Normalized CVSS base score.
  - Subgraph centrality metric (PageRank / Betweenness).
  - Downstream blast radius (affected package and application count).
  - Maximum application criticality score.

### Step 11: Demonstrate AI Explanation & Fail-Safe Behavior
- In the inspector modal, observe the **AI Explanation** panel:
  - When Gemini is available: Click **Generate AI Explanation** to produce structured, evidence-grounded narratives (Executive Summary, Structural Rationale, Contributing Factors, Mitigation Guidance, and Cited Evidence IDs).
  - If the upstream Gemini API experiences temporary high demand (HTTP 503 UNAVAILABLE) or if `GEMINI_API_KEY` is omitted:
    - RippleGuard fails gracefully without crashing.
    - Status badge displays **AI Unavailable** or **Failure Logged**.
    - Safe fallback banner displays: *"AI explanation unavailable. Deterministic RippleGuard analysis is still available."*
    - **Crucial Invariance**: The deterministic risk score, priority rank, and priority band remain 100% intact and sovereign.

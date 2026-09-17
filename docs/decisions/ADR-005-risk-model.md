# ADR-005: RippleGuard Structural Risk Model & Mitigation Priority Architecture

## Status
Accepted

## Context
Software supply chains contain thousands of transitive packages. Traditional software composition analysis (SCA) tools rank vulnerabilities strictly by their CVSS base score or publish date ("loudest CVE first"). This produces overwhelming alert fatigue and misallocates engineering remediation effort:
1. High-severity CVEs in isolated leaf packages with zero downstream dependents are prioritized over moderate vulnerabilities in foundational runtime packages that reach production critical banking systems.
2. CVSS alone lacks graph context: it cannot quantify structural centrality (how deeply embedded a component is in the ecosystem) or blast radius (how many applications and packages are impacted if compromised).
3. Teams lack a deterministic, evidence-grounded framework to answer: **"Which dependency vulnerability should we remediate first to maximize risk reduction across our applications?"**

## Decision
We implement the **RippleGuard Proposed Structural Risk Model**, combining four deterministic components:

$$\text{Risk} = (w_{\text{sev}} \times \text{Severity}) + (w_{\text{cent}} \times \text{Centrality}) + (w_{\text{blast}} \times \text{Blast Radius}) + (w_{\text{crit}} \times \text{Application Criticality})$$

$$\text{Risk Score} = \text{Risk} \times 100 \quad (\text{Range: } [0, 100])$$

### 1. The Four Risk Factors
1. **Severity ($[0, 1]$)**: Normalized CVSS v3/v4 base score ($\text{Base Score} / 10.0$). If multiple vectors exist, the highest base score is selected. Unscored vulnerabilities receive null raw score, 0.0 normalized score, and are categorized as `UNSCORED`.
2. **Centrality ($[0, 1]$)**: Composite of PageRank ($0.50$) and Betweenness Centrality ($0.50$) computed **strictly on the package-only subgraph** (applications excluded to avoid skewing dependency authority). Normalized via min-max scaling to $[0, 1]$ (defaulting to 0.0 when values are uniform).
3. **Blast Radius ($[0, 1]$)**: Composite of Application Reach and Package Reach using Phase 4 consistent reach metrics:
   $$\text{Blast Radius} = 0.70 \times \left(\frac{\text{affected\_apps}}{\text{total\_project\_apps}}\right) + 0.30 \times \min\left(1.0, \frac{\text{affected\_packages}}{\max(1, \text{total\_packages}-1)}\right)$$
4. **Application Criticality ($[0, 1]$)**: The maximum criticality score among all downstream applications reached by the vulnerability propagation path:
   - `CRITICAL` = 1.00
   - `HIGH` = 0.75
   - `MEDIUM` = 0.50
   - `LOW` = 0.25
   If no application is reached, defaults to 0.00.

### 2. Configurable Weights & Default Values
Weights are project-configurable via `RiskProfile`, but must strictly sum to $1.00$:
- Severity Weight ($w_{\text{sev}}$): `0.30`
- Centrality Weight ($w_{\text{cent}}$): `0.25`
- Blast Radius Weight ($w_{\text{blast}}$): `0.25`
- Application Criticality Weight ($w_{\text{crit}}$): `0.20`

### 3. Proposed Decision Model Notice
> **IMPORTANT**: The RippleGuard Structural Risk Model is an explicit **proposed decision lens**, NOT an established industry benchmark (such as CVSS or EPSS). It provides security teams with an evidence-grounded heuristic to discover high-leverage remediation targets.

### 4. Deterministic Ranking & Tie-Breaking
Mitigation priority ranks are ordered deterministically by:
1. `risk_score` (Descending)
2. `blast_radius_score` (Descending)
3. `centrality_score` (Descending)
4. `severity_normalized` (Descending)
5. `package_id` (Ascending)
6. `vulnerability_id` (Ascending)

Priority bands are assigned deterministically:
- `CRITICAL`: 75.00 – 100.00
- `HIGH`: 50.00 – 74.99
- `MODERATE`: 25.00 – 49.99
- `LOW`: 0.00 – 24.99
- `UNSCORED`: Missing CVSS (severity_normalized = null, risk_score = null, priority_rank = null)

### 5. Unscored Severity Handling
Vulnerabilities lacking parseable CVSS base scores are never assigned artificial numerical zeros or discarded:
- `severity_normalized = null`
- `risk_score = null`
- `priority_band = "UNSCORED"`
- `priority_rank = null`
Unscored vulnerabilities remain completely visible in the inventory and priority responses, but are excluded from the ranked scored results (ranks 1..N).

## Alternatives Considered

### 1. Severity-Only Ranking (Traditional SCA / CVSS Base)
- *Why rejected*: Leads to alert fatigue. A leaf package with CVSS 9.8 that affects zero downstream services is prioritized over a CVSS 6.5 flaw in a foundational middleware that reaches every mission-critical system.

### 2. CVSS $\times$ Reach Multiplicative Product
- *Why rejected*: Highly vulnerable to boundary distortions (e.g. any factor being zero collapses the score entirely). Multiplicative models also make proportional component attribution uninterpretable to security engineers.

### 3. Centrality-Only Ranking
- *Why rejected*: Ignores vulnerability exploitability and severity. A harmless cosmetic bug in a central package would be prioritized over remote code execution in an application entrypoint.

### 4. Black-box Machine Learning / LLM-Based Scoring
- *Why rejected*: Lacks auditability, determinism, and explainability. Security teams and regulators require mathematically reproducible priority ranking where each point in the score traces back to concrete graph facts.

## Tradeoffs & Safeguards
- **Centrality Computation Scalability**: Exact betweenness centrality runs in $\mathcal{O}(V \cdot E)$. For subgraphs with $> 2,000$ packages, RippleGuard switches to randomized landmark sampling ($k=100$) with a fixed random seed (`42`), tagging the result as `centrality_approximate = True`.
- **PageRank Convergence & Fallback**:
  - *Why fallback exists*: Pathological graph topologies (e.g. periodic cycles, bipartite sinks, extreme damping tolerances) or environments lacking numerical acceleration can fail power iteration convergence within `PAGERANK_MAX_ITER` (200 iterations).
  - *Why deterministic*: When convergence fails, the engine substitutes a uniform distribution $\{pid: 1.0 / N\}$ where each package receives identical raw probability. Normalization across identical values produces $0.0$ deterministically with zero stochasticity or ranking variance.
  - *How marked/audited*: Emits a structured log warning and flags `centrality_approximate = True` on all computed metrics and persisted database records.
- **Snapshot Immutability**: Each risk analysis execution snapshots the exact active weights in `weights_snapshot`, guaranteeing historical reproducibility even if the project's risk profile is later modified.

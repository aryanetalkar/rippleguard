# RippleGuard API Documentation

This document describes the implemented endpoints in **Phase 4 (Ripple Propagation Engine)**.

Interactive OpenAPI documentation is accessible at `/api/v1/docs` (Swagger UI) and `/api/v1/redoc` (ReDoc).

---

## Base URLs

- **Local Development**: `http://localhost:8000`
- **Prefix**: `/api/v1`

---

## 1. System Health

- `GET /health` -> `{"status": "ok", "service": "rippleguard-api"}`
- `GET /api/v1/health` -> `{"status": "ok", "service": "rippleguard-api"}`

---

## 2. Projects & Dependency Graph APIs

- `POST /api/v1/projects` (Create project)
- `GET /api/v1/projects` (List projects)
- `POST /api/v1/projects/{project_id}/sbom` (Ingest CycloneDX SBOM)
- `GET /api/v1/projects/{project_id}/sbom` (Ingestion history)
- `GET /api/v1/projects/{project_id}/graph` (Graph summary metrics)
- `GET /api/v1/projects/{project_id}/graph/nodes` (Normalized graph nodes)
- `GET /api/v1/projects/{project_id}/graph/edges` (Directed dependency edges)

---

## 3. Vulnerability Intelligence APIs (Phase 3)

- `POST /api/v1/projects/{project_id}/vulnerabilities/scan` (Trigger OSV scan)
- `GET /api/v1/projects/{project_id}/vulnerabilities/scans` (Scan history)
- `GET /api/v1/projects/{project_id}/vulnerabilities` (List project vulnerabilities)
- `GET /api/v1/packages/{package_id}/vulnerabilities` (Package-level vulnerabilities)

---

## 4. Ripple Propagation Engine APIs (Phase 4)

### 4.1 Trigger Ripple Analysis
Executes a deterministic reverse BFS impact traversal starting from a compromised seed package.

- **URL**: `POST /api/v1/projects/{project_id}/ripple/analyses`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "seed_package_id": 3,
    "seed_vulnerability_id": 1
  }
  ```
  *(Note: `seed_vulnerability_id` is optional. Omitting it runs a hypothetical compromise simulation).*
- **Response**: `201 Created`
  ```json
  {
    "analysis_id": 1,
    "project_id": 1,
    "status": "success",
    "seed_package": {
      "id": 3,
      "name": "package-c",
      "version": "1.0.0",
      "ecosystem": "npm",
      "purl": "pkg:npm/package-c@1.0.0"
    },
    "seed_vulnerability": {
      "id": 1,
      "osv_id": "GHSA-test-1234",
      "summary": "Denial of Service in package-c"
    },
    "sbom_ingestion_id": 1,
    "vulnerability_scan_id": 1,
    "summary": {
      "max_depth": 2,
      "affected_package_count": 3,
      "affected_application_count": 1,
      "direct_dependent_count": 2,
      "transitive_dependent_count": 0,
      "truncated": false,
      "truncation_reason": null
    },
    "started_at": "2026-09-17T15:00:00Z",
    "completed_at": "2026-09-17T15:00:01Z",
    "error_message": null,
    "created_at": "2026-09-17T15:00:01Z"
  }
  ```

---

### 4.2 List Ripple Analyses History
Returns execution history of ripple analyses for the project.

- **URL**: `GET /api/v1/projects/{project_id}/ripple/analyses`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "project_id": 1,
    "total": 1,
    "analyses": [
      {
        "id": 1,
        "project_id": 1,
        "status": "success",
        "seed_package_id": 3,
        "seed_package_name": "package-c",
        "seed_package_version": "1.0.0",
        "seed_vulnerability_osv_id": "GHSA-test-1234",
        "max_depth": 2,
        "affected_package_count": 3,
        "affected_application_count": 1,
        "direct_dependent_count": 2,
        "transitive_dependent_count": 0,
        "truncated": false,
        "truncation_reason": null,
        "created_at": "2026-09-17T15:00:01Z"
      }
    ]
  }
  ```

---

### 4.3 Get Single Ripple Analysis
Returns metadata, summary metrics, and truncation state for a specific analysis run.

- **URL**: `GET /api/v1/projects/{project_id}/ripple/analyses/{analysis_id}`
- **Method**: `GET`
- **Response**: `200 OK`

---

### 4.4 Get Ripple Analysis Affected Nodes
Returns all affected packages and downstream applications reached during the impact traversal.

- **URL**: `GET /api/v1/projects/{project_id}/ripple/analyses/{analysis_id}/nodes`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "analysis_id": 1,
    "total_nodes": 4,
    "seed_package_id": 3,
    "nodes": [
      {
        "node_type": "package",
        "id": "pkg:3",
        "db_id": 3,
        "name": "package-c",
        "version": "1.0.0",
        "ecosystem": "npm",
        "depth": 0,
        "is_seed": true,
        "is_direct": false,
        "shortest_path_length": 0
      },
      {
        "node_type": "package",
        "id": "pkg:1",
        "db_id": 1,
        "name": "package-a",
        "version": "1.0.0",
        "ecosystem": "npm",
        "depth": 1,
        "is_seed": false,
        "is_direct": true,
        "shortest_path_length": 1
      },
      {
        "node_type": "application",
        "id": "app:1",
        "db_id": 1,
        "name": "Application A",
        "version": "1.0.0",
        "ecosystem": null,
        "depth": 2,
        "is_seed": false,
        "is_direct": false,
        "shortest_path_length": 2
      }
    ]
  }
  ```

---

### 4.5 Get Ripple Analysis Propagation Paths
Returns deterministic unweighted shortest propagation paths from the compromised seed to each reached node.

- **URL**: `GET /api/v1/projects/{project_id}/ripple/analyses/{analysis_id}/paths`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "analysis_id": 1,
    "total_paths": 3,
    "paths": [
      {
        "id": 1,
        "target": {
          "node_type": "application",
          "id": "app:1",
          "db_id": 1,
          "name": "Application A",
          "version": "1.0.0"
        },
        "path": [
          {
            "node_type": "package",
            "id": "pkg:3",
            "db_id": 3,
            "name": "package-c",
            "version": "1.0.0",
            "depth": 0
          },
          {
            "node_type": "package",
            "id": "pkg:1",
            "db_id": 1,
            "name": "package-a",
            "version": "1.0.0",
            "depth": 1
          },
          {
            "node_type": "application",
            "id": "app:1",
            "db_id": 1,
            "name": "Application A",
            "version": "1.0.0",
            "depth": 2
          }
        ],
        "path_length": 2
      }
    ]
  }
  ```

---

---

## 5. Structural Risk & Mitigation Priority APIs (Phase 5)

### 5.1 Get Project Risk Profile
Retrieves the active configurable risk weights for a project.

- **URL**: `GET /api/v1/projects/{project_id}/risk/profile`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "id": 1,
    "project_id": 1,
    "severity_weight": 0.30,
    "centrality_weight": 0.25,
    "blast_radius_weight": 0.25,
    "application_criticality_weight": 0.20,
    "created_at": "2026-09-17T20:00:00Z",
    "updated_at": "2026-09-17T20:00:00Z"
  }
  ```

### 5.2 Update Project Risk Profile
Updates the active configurable risk weights. Sum of weights must strictly equal 1.00.

- **URL**: `PUT /api/v1/projects/{project_id}/risk/profile`
- **Method**: `PUT`
- **Request Body**:
  ```json
  {
    "severity_weight": 0.35,
    "centrality_weight": 0.25,
    "blast_radius_weight": 0.25,
    "application_criticality_weight": 0.15
  }
  ```
- **Response**: `200 OK`

### 5.3 Update Application Criticality Tier
Configures an application's asset criticality tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

- **URL**: `PATCH /api/v1/projects/{project_id}/applications/{application_id}/criticality`
- **Method**: `PATCH`
- **Request Body**:
  ```json
  {
    "tier": "CRITICAL"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "application_id": 1,
    "name": "Production Banking Core",
    "version": "1.0.0",
    "criticality_tier": "CRITICAL",
    "criticality_score": 1.00,
    "criticality_source": "manual"
  }
  ```

### 5.4 List Applications with Criticality
- **URL**: `GET /api/v1/projects/{project_id}/applications`
- **Method**: `GET`
- **Response**: `200 OK`

### 5.5 Execute Structural Risk Analysis
Executes a multi-factor structural risk calculation across all vulnerable packages in the project.

- **URL**: `POST /api/v1/projects/{project_id}/risk/analyses`
- **Method**: `POST`
- **Response**: `201 Created`
  ```json
  {
    "analysis_id": 1,
    "project_id": 1,
    "status": "success",
    "pair_count": 2,
    "vulnerability_count": 2,
    "package_count": 2,
    "weights_snapshot": {
      "severity_weight": 0.30,
      "centrality_weight": 0.25,
      "blast_radius_weight": 0.25,
      "application_criticality_weight": 0.20
    },
    "created_at": "2026-09-17T20:00:00Z"
  }
  ```

### 5.6 Get Latest Ranked Mitigation Priority
Retrieves the latest deterministic mitigation priority rankings for a project.

- **URL**: `GET /api/v1/projects/{project_id}/risk/priority`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "analysis_id": 1,
    "project_id": 1,
    "total_results": 2,
    "weights_used": {
      "severity_weight": 0.30,
      "centrality_weight": 0.25,
      "blast_radius_weight": 0.25,
      "application_criticality_weight": 0.20
    },
    "results": [
      {
        "id": 1,
        "risk_analysis_id": 1,
        "package_id": 1,
        "package_name": "core-runtime-a",
        "package_version": "1.0.0",
        "package_purl": "pkg:npm/core-runtime-a@1.0.0",
        "vulnerability_id": 1,
        "vulnerability_osv_id": "CVE-2024-MODERATE-A",
        "vulnerability_summary": "Moderate severity flaw in core-runtime-a",
        "priority_rank": 1,
        "risk_score": 78.4,
        "priority_band": "HIGH",
        "severity_raw_score": 5.2,
        "severity_normalized": 0.52,
        "pagerank_score": 0.24,
        "betweenness_score": 0.12,
        "centrality_score": 0.85,
        "affected_application_count": 1,
        "affected_downstream_package_count": 3,
        "blast_radius_score": 0.85,
        "application_criticality_score": 1.00,
        "dependency_depth": 2,
        "centrality_approximate": false,
        "explanation": {
          "text": "Priority rank #1: core-runtime-a@1.0.0 has a computed risk score of 78.4...",
          "metrics": { ... }
        },
        "mitigation_evidence": { ... }
      }
    ],
    "created_at": "2026-09-17T20:00:00Z"
  }
  ```

## 6. AI Explanation & Evidence Layer APIs (Phase 6)

### 6.1 Generate AI Explanation for a Risk Result
Generates or retrieves a cached, evidence-grounded AI explanation for a specific finding.

- **URL**: `POST /api/v1/projects/{project_id}/risk/results/{risk_result_id}/explanation`
- **Method**: `POST`
- **Response**: `200 OK`
  ```json
  {
    "explanation_id": 1,
    "risk_result_id": 1,
    "status": "success",
    "model_name": "gemini-3.8-flash",
    "prompt_version": "1.0",
    "evidence_version": "1.0",
    "evidence_hash": "a9b8c7...",
    "summary": "Package lodash is ranked first because its moderate-severity vulnerability combines with substantial structural reach and critical downstream applications.",
    "why_priority": "The package reaches 40 downstream applications and has high structural centrality...",
    "key_factors": [
      "High downstream application reach",
      "High structural centrality",
      "Critical affected applications"
    ],
    "mitigation_guidance": "Review the fixed-version information supplied by the OSV advisory and prioritize remediation of this dependency.",
    "limitations": [
      "RippleGuard's score is a proposed configurable decision model and should be reviewed alongside organizational security context."
    ],
    "evidence_ids": [
      "risk_score",
      "priority_rank",
      "priority_band",
      "cvss_score",
      "centrality_score",
      "affected_application_count",
      "application_criticality"
    ],
    "failed_reason": null,
    "generated_at": "2026-09-17T21:00:00Z"
  }
  ```

---

### 6.2 Get Latest Successful AI Explanation
Retrieves the most recent verified AI explanation for a risk finding.

- **URL**: `GET /api/v1/projects/{project_id}/risk/results/{risk_result_id}/explanation`
- **Method**: `GET`
- **Response**: `200 OK` (schema identical to 6.1) or `404 Not Found` if not generated yet.

---

### 6.3 Batch Generate Explanations for Risk Analysis
Generates explanations for all scored findings in an analysis, bounded by `MAX_EXPLANATIONS_PER_REQUEST = 25`.

- **URL**: `POST /api/v1/projects/{project_id}/risk/analyses/{analysis_id}/explanations`
- **Method**: `POST`
- **Response**: `200 OK`
  ```json
  {
    "analysis_id": 1,
    "total_requested": 5,
    "successful_count": 5,
    "failed_count": 0,
    "explanations": [ ... ]
  }
  ```
- **Error Response**: `400 Bad Request` if scored count exceeds 25.

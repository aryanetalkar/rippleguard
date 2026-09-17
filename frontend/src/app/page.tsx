"use client";

import React, { useEffect, useState } from "react";
import {
  Upload,
  CheckCircle2,
  AlertCircle,
  FileCode,
  Layers,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  Bug,
  ExternalLink,
  ShieldAlert,
  AlertTriangle,
  Radio,
  Workflow,
  History,
  GitCommit,
  Check,
  SlidersHorizontal,
  Scale,
  BarChart3,
  HelpCircle,
  X,
  Target,
  ShieldX,
  Building,
  Activity,
  Sparkles,
  Bot,
} from "lucide-react";
import RippleGraph, { RippleNodeData, RipplePathData } from "../components/RippleGraph";

const API_BASE = "http://localhost:8000/api/v1";

interface IngestionResult {
  ingestion_id: number;
  project_id: number;
  application_id: number | null;
  application_name: string | null;
  application_version: string | null;
  filename: string;
  sha256: string;
  spec_version: string;
  status: string;
  package_count: number;
  dependency_count: number;
  created_at: string;
}

interface GraphSummary {
  project_id: number;
  application_count: number;
  package_count: number;
  dependency_count: number;
  direct_dependency_count: number;
  transitive_package_count: number;
  unresolved_reference_count: number;
  latest_spec_version: string | null;
  latest_ingestion_id: number | null;
  applications: string[];
}

interface GraphNode {
  id: string;
  node_type: string;
  db_id?: number;
  name: string;
  version: string | null;
  ecosystem: string | null;
  purl: string | null;
}

interface GraphEdge {
  id: number;
  source: string;
  target: string;
  source_name: string;
  target_name: string;
  direct: boolean;
  dependency_type: string;
}

interface VulnerabilityItem {
  id: number;
  osv_id: string;
  summary: string | null;
  details: string | null;
  published_at: string | null;
  modified_at: string | null;
  withdrawn_at: string | null;
  is_withdrawn: boolean;
  aliases: string[];
  severity_data: Array<{ type?: string; score?: string }>;
  packages: Array<{
    id: number;
    name: string;
    version: string;
    ecosystem: string;
    purl: string | null;
  }>;
}

interface ScanResult {
  scan_id: number;
  project_id: number;
  status: string;
  package_count: number;
  vulnerable_package_count: number;
  vulnerability_count: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

interface RippleAnalysisSummary {
  max_depth: number;
  affected_package_count: number;
  affected_application_count: number;
  direct_dependent_count: number;
  transitive_dependent_count: number;
  truncated: boolean;
  truncation_reason: string | null;
}

interface RippleAnalysisResponse {
  analysis_id: number;
  project_id: number;
  status: string;
  seed_package: {
    id: number;
    name: string;
    version: string;
    ecosystem: string;
    purl: string | null;
  };
  seed_vulnerability: {
    id: number;
    osv_id: string;
    summary: string | null;
  } | null;
  summary: RippleAnalysisSummary;
  started_at: string;
  completed_at: string | null;
  created_at: string;
}

interface RippleHistoryItem {
  id: number;
  project_id: number;
  status: string;
  seed_package_id: number;
  seed_package_name: string;
  seed_package_version: string;
  seed_vulnerability_osv_id: string | null;
  max_depth: number;
  affected_package_count: number;
  affected_application_count: number;
  direct_dependent_count: number;
  transitive_dependent_count: number;
  truncated: boolean;
  truncation_reason: string | null;
  created_at: string;
}

// Phase 5 Interfaces
interface ApplicationItem {
  application_id: number;
  name: string;
  version: string | null;
  criticality_tier: string;
  criticality_score: number;
  criticality_source: string;
}

interface RiskProfileData {
  severity_weight: number;
  centrality_weight: number;
  blast_radius_weight: number;
  application_criticality_weight: number;
}

interface RiskResultItem {
  id: number;
  risk_analysis_id?: number;
  analysis_id?: number;
  package_id: number;
  package_name: string;
  package_version: string;
  package_purl: string | null;
  package_ecosystem?: string;
  vulnerability_id: number;
  vulnerability_osv_id: string;
  vulnerability_summary: string | null;
  priority_rank: number | null;
  risk_score: number | null;
  priority_band: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNSCORED" | string;
  cvss_score?: number | null;
  cvss_version?: string | null;
  severity_raw_score?: number | null;
  severity_normalized?: number | null;
  pagerank?: number | null;
  pagerank_score?: number | null;
  betweenness?: number | null;
  betweenness_score?: number | null;
  centrality_score?: number | null;
  affected_application_count: number;
  affected_downstream_package_count: number;
  blast_radius_score?: number | null;
  application_criticality_score?: number | null;
  max_application_criticality?: string | null;
  dependency_depth: number | null;
  centrality_approximate: boolean;
  reason?: string | null;
  explanation?: any;
  mitigation_evidence?: any;
}

interface RiskPriorityResponse {
  analysis_id: number;
  project_id: number;
  total_results: number;
  weights_used: {
    severity_weight: number;
    centrality_weight: number;
    blast_radius_weight: number;
    application_criticality_weight: number;
  };
  results: RiskResultItem[];
  created_at: string;
}

interface AIExplanation {
  explanation_id: number;
  risk_result_id: number;
  status: "not_generated" | "generating" | "success" | "failed" | "validation_failed";
  model_name: string;
  prompt_version: string;
  evidence_version: string;
  evidence_hash: string;
  summary?: string | null;
  why_priority?: string | null;
  key_factors?: string[] | null;
  mitigation_guidance?: string | null;
  limitations?: string[] | null;
  evidence_ids?: string[] | null;
  failed_reason?: string | null;
  generated_at?: string;
}

export default function HomePage() {
  const [projectId, setProjectId] = useState<number | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [scanErrorMsg, setScanErrorMsg] = useState<string | null>(null);
  const [ingestion, setIngestion] = useState<IngestionResult | null>(null);
  const [graphSummary, setGraphSummary] = useState<GraphSummary | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityItem[]>([]);
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "withdrawn">("all");

  // Phase 4: Ripple Propagation State
  const [simulatingRipple, setSimulatingRipple] = useState(false);
  const [rippleError, setRippleError] = useState<string | null>(null);
  const [activeRipple, setActiveRipple] = useState<RippleAnalysisResponse | null>(null);
  const [rippleNodes, setRippleNodes] = useState<RippleNodeData[]>([]);
  const [ripplePaths, setRipplePaths] = useState<RipplePathData[]>([]);
  const [hypoSeedPkgId, setHypoSeedPkgId] = useState<string>("");
  const [rippleHistory, setRippleHistory] = useState<RippleHistoryItem[]>([]);

  // Phase 5: Structural Risk & Mitigation Priority State
  const [applications, setApplications] = useState<ApplicationItem[]>([]);
  const [riskProfile, setRiskProfile] = useState<RiskProfileData>({
    severity_weight: 0.30,
    centrality_weight: 0.25,
    blast_radius_weight: 0.25,
    application_criticality_weight: 0.20,
  });
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileMsg, setProfileMsg] = useState<string | null>(null);
  const [analyzingRisk, setAnalyzingRisk] = useState(false);
  const [riskError, setRiskError] = useState<string | null>(null);
  const [latestPriority, setLatestPriority] = useState<RiskPriorityResponse | null>(null);
  const [selectedModalResult, setSelectedModalResult] = useState<RiskResultItem | null>(null);

  // Phase 6: AI Explanation State
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  const [aiStatus, setAiStatus] = useState<"not_generated" | "generating" | "success" | "failed" | "validation_failed">("not_generated");
  const [aiError, setAiError] = useState<string | null>(null);

  // Initialize or fetch default project
  useEffect(() => {
    async function initProject() {
      try {
        const res = await fetch(`${API_BASE}/projects`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: "Default Project",
            description: "Default workspace for supply-chain risk intelligence",
          }),
        });
        if (res.ok) {
          const data = await res.json();
          setProjectId(data.id);
          fetchGraphData(data.id);
          fetchVulnerabilities(data.id);
          fetchRippleHistory(data.id);
          fetchApplications(data.id);
          fetchRiskProfile(data.id);
          fetchLatestPriority(data.id);
        }
      } catch {
        // Backend may not be running locally during static build
      }
    }
    initProject();
  }, []);

  async function fetchGraphData(pId: number) {
    try {
      const [sumRes, nodesRes, edgesRes] = await Promise.all([
        fetch(`${API_BASE}/projects/${pId}/graph`),
        fetch(`${API_BASE}/projects/${pId}/graph/nodes`),
        fetch(`${API_BASE}/projects/${pId}/graph/edges`),
      ]);

      if (sumRes.ok) setGraphSummary(await sumRes.json());
      if (nodesRes.ok) {
        const n = await nodesRes.json();
        setNodes(n.nodes || []);
      }
      if (edgesRes.ok) {
        const e = await edgesRes.json();
        setEdges(e.edges || []);
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchVulnerabilities(pId: number) {
    try {
      const res = await fetch(`${API_BASE}/projects/${pId}/vulnerabilities`);
      if (res.ok) {
        const data = await res.json();
        setVulnerabilities(data.items || []);
      }
      const scansRes = await fetch(`${API_BASE}/projects/${pId}/vulnerabilities/scans`);
      if (scansRes.ok) {
        const sData = await scansRes.json();
        if (sData.items && sData.items.length > 0) {
          setLatestScan(sData.items[0]);
        }
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchRippleHistory(pId: number) {
    try {
      const res = await fetch(`${API_BASE}/projects/${pId}/ripple/analyses`);
      if (res.ok) {
        const data = await res.json();
        setRippleHistory(data.analyses || []);
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchApplications(pId: number) {
    try {
      const res = await fetch(`${API_BASE}/projects/${pId}/applications`);
      if (res.ok) {
        const data = await res.json();
        setApplications(data || []);
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchRiskProfile(pId: number) {
    try {
      const res = await fetch(`${API_BASE}/projects/${pId}/risk/profile`);
      if (res.ok) {
        const data = await res.json();
        setRiskProfile({
          severity_weight: data.severity_weight,
          centrality_weight: data.centrality_weight,
          blast_radius_weight: data.blast_radius_weight,
          application_criticality_weight: data.application_criticality_weight,
        });
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchLatestPriority(pId: number) {
    try {
      const res = await fetch(`${API_BASE}/projects/${pId}/risk/priority`);
      if (res.ok) {
        const data = await res.json();
        setLatestPriority(data);
      }
    } catch {
      // Ignored if offline
    }
  }

  async function fetchOrGenerateExplanation(riskResultId: number, forceGenerate = false) {
    if (!projectId) return;
    setAiStatus("generating");
    setAiError(null);

    try {
      if (!forceGenerate) {
        const getRes = await fetch(`${API_BASE}/projects/${projectId}/risk/results/${riskResultId}/explanation`);
        if (getRes.ok) {
          const data = await getRes.json();
          setAiExplanation(data);
          setAiStatus(data.status);
          if (data.status === "failed") {
            setAiError(data.failed_reason || "AI explanation unavailable. Deterministic analysis remains available.");
          } else if (data.status === "validation_failed") {
            setAiError(data.failed_reason || "AI explanation rejected by RippleGuard evidence guardrails.");
          }
          return;
        }
      }

      const postRes = await fetch(`${API_BASE}/projects/${projectId}/risk/results/${riskResultId}/explanation`, {
        method: "POST",
      });
      const data = await postRes.json();
      if (!postRes.ok) {
        setAiStatus("failed");
        setAiError(data.detail || "AI explanation unavailable. Deterministic analysis remains available.");
        return;
      }

      setAiExplanation(data);
      setAiStatus(data.status);
      if (data.status === "failed") {
        setAiError(data.failed_reason || "AI explanation unavailable. Deterministic analysis remains available.");
      } else if (data.status === "validation_failed") {
        setAiError(data.failed_reason || "AI explanation rejected by RippleGuard evidence guardrails.");
      }
    } catch {
      setAiStatus("failed");
      setAiError("AI explanation unavailable. Deterministic analysis remains available.");
    }
  }

  async function handleSimulateRipple(pkgId: number, vulnId?: number) {
    if (!projectId) return;

    setSimulatingRipple(true);
    setRippleError(null);

    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/ripple/analyses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          seed_package_id: pkgId,
          seed_vulnerability_id: vulnId || null,
        }),
      });

      const analysisData = await res.json();
      if (!res.ok) {
        setRippleError(analysisData.detail || "Ripple simulation failed.");
        return;
      }

      setActiveRipple(analysisData);

      const [nodesRes, pathsRes] = await Promise.all([
        fetch(`${API_BASE}/projects/${projectId}/ripple/analyses/${analysisData.analysis_id}/nodes`),
        fetch(`${API_BASE}/projects/${projectId}/ripple/analyses/${analysisData.analysis_id}/paths`),
      ]);

      if (nodesRes.ok) {
        const nData = await nodesRes.json();
        setRippleNodes(nData.nodes || []);
      }
      if (pathsRes.ok) {
        const pData = await pathsRes.json();
        setRipplePaths(pData.paths || []);
      }

      await fetchRippleHistory(projectId);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Network error during simulation.";
      setRippleError(message);
    } finally {
      setSimulatingRipple(false);
    }
  }

  async function handleLoadPastRipple(analysisId: number) {
    if (!projectId) return;

    setSimulatingRipple(true);
    setRippleError(null);

    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/ripple/analyses/${analysisId}`);
      if (!res.ok) throw new Error("Failed to load ripple analysis.");
      const analysisData = await res.json();
      setActiveRipple(analysisData);

      const [nodesRes, pathsRes] = await Promise.all([
        fetch(`${API_BASE}/projects/${projectId}/ripple/analyses/${analysisId}/nodes`),
        fetch(`${API_BASE}/projects/${projectId}/ripple/analyses/${analysisId}/paths`),
      ]);

      if (nodesRes.ok) {
        const nData = await nodesRes.json();
        setRippleNodes(nData.nodes || []);
      }
      if (pathsRes.ok) {
        const pData = await pathsRes.json();
        setRipplePaths(pData.paths || []);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to load past analysis.";
      setRippleError(message);
    } finally {
      setSimulatingRipple(false);
    }
  }

  async function handleUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!file || !projectId) {
      setErrorMsg("Please select a CycloneDX JSON file to upload.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/sbom`, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || "Failed to parse and ingest SBOM.");
      } else {
        setIngestion(data);
        await Promise.all([
          fetchGraphData(projectId),
          fetchApplications(projectId),
        ]);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Connection to backend service failed.";
      setErrorMsg(`Network/Backend Error: ${message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleScan() {
    if (!projectId) return;

    setScanning(true);
    setScanErrorMsg(null);

    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/vulnerabilities/scan`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) {
        setScanErrorMsg(data.detail || "Scan failed.");
      } else {
        setLatestScan(data);
        await fetchVulnerabilities(projectId);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to connect to backend.";
      setScanErrorMsg(`Scan Error: ${message}`);
    } finally {
      setScanning(false);
    }
  }

  // Phase 5 Handlers
  async function handleUpdateCriticality(appId: number, tier: string) {
    if (!projectId) return;
    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/applications/${appId}/criticality`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier }),
      });
      if (res.ok) {
        await fetchApplications(projectId);
      }
    } catch {
      // Ignored
    }
  }

  const weightSum = Number(
    (
      riskProfile.severity_weight +
      riskProfile.centrality_weight +
      riskProfile.blast_radius_weight +
      riskProfile.application_criticality_weight
    ).toFixed(2)
  );
  const isWeightValid = Math.abs(weightSum - 1.0) < 0.001;

  async function handleSaveRiskProfile() {
    if (!projectId) return;
    if (!isWeightValid) {
      setProfileMsg("Weights must strictly sum to 1.00 (100%).");
      return;
    }

    setSavingProfile(true);
    setProfileMsg(null);
    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/risk/profile`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(riskProfile),
      });
      if (res.ok) {
        setProfileMsg("Risk weights successfully saved!");
        setTimeout(() => setProfileMsg(null), 3000);
      } else {
        const data = await res.json();
        setProfileMsg(data.detail || "Failed to update weights.");
      }
    } catch {
      setProfileMsg("Network error saving profile.");
    } finally {
      setSavingProfile(false);
    }
  }

  function handleResetDefaultWeights() {
    setRiskProfile({
      severity_weight: 0.30,
      centrality_weight: 0.25,
      blast_radius_weight: 0.25,
      application_criticality_weight: 0.20,
    });
  }

  async function handleAnalyzeRisk() {
    if (!projectId) return;
    setAnalyzingRisk(true);
    setRiskError(null);

    try {
      const res = await fetch(`${API_BASE}/projects/${projectId}/risk/analyses`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) {
        setRiskError(data.detail || "Risk analysis failed.");
      } else {
        await fetchLatestPriority(projectId);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Error executing risk analysis.";
      setRiskError(message);
    } finally {
      setAnalyzingRisk(false);
    }
  }

  const filteredVulns = vulnerabilities.filter((v) => {
    if (statusFilter === "active") return !v.is_withdrawn;
    if (statusFilter === "withdrawn") return v.is_withdrawn;
    return true;
  });

  const packageNodes = nodes.filter((n) => n.node_type === "package");

  return (
    <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8 space-y-12">
      {/* Platform Title */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/20 bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-400">
          <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
          RippleGuard Intelligence Monolith · Phase 6 Active
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl bg-gradient-to-r from-blue-400 via-indigo-300 to-violet-400 bg-clip-text text-transparent">
          Software Supply-Chain Risk Intelligence
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          Deterministic Dependency Graphs · OSV Vulnerabilities · Ripple Propagation Engine · Structural Risk & Mitigation Priority
        </p>
      </div>

      {/* Main Ingestion & Vulnerability Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* SBOM Ingestion Card */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Upload className="h-5 w-5 text-blue-400" />
            <h2 className="text-base font-semibold text-slate-200">Ingest CycloneDX SBOM</h2>
          </div>

          <form onSubmit={handleUpload} className="space-y-4">
            <div className="flex flex-col items-center justify-center border-2 border-dashed border-slate-700 rounded-lg p-6 hover:border-slate-500 transition cursor-pointer bg-slate-950/40">
              <FileCode className="h-8 w-8 text-slate-400 mb-2" />
              <label htmlFor="sbom-file" className="cursor-pointer text-xs text-blue-400 hover:text-blue-300 font-medium">
                {file ? file.name : "Select CycloneDX JSON file"}
              </label>
              <input
                id="sbom-file"
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
              />
              <span className="text-[10px] text-slate-500 mt-1">Supports CycloneDX JSON 1.4, 1.5, 1.6</span>
            </div>

            {errorMsg && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !file}
              className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-semibold shadow transition flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Parsing & Persisting...
                </>
              ) : (
                "Upload & Construct Dependency Graph"
              )}
            </button>
          </form>
        </div>

        {/* Vulnerability Intelligence Card */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Bug className="h-5 w-5 text-indigo-400" />
            <h2 className="text-base font-semibold text-slate-200">OSV Vulnerability Intelligence</h2>
          </div>

          <p className="text-xs text-slate-400">
            Query OSV.dev for known vulnerabilities affecting exact ingested package versions.
          </p>

          {scanErrorMsg && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{scanErrorMsg}</span>
            </div>
          )}

          {latestScan && (
            <div className="grid grid-cols-2 gap-2 text-xs bg-slate-950/40 p-3 rounded-lg border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] block">SCAN STATUS</span>
                <span className="font-mono text-emerald-400 uppercase font-semibold">{latestScan.status}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">VULNERABILITIES FOUND</span>
                <span className="font-mono text-amber-400 font-semibold">{latestScan.vulnerability_count}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">VULNERABLE PACKAGES</span>
                <span className="font-mono text-white">{latestScan.vulnerable_package_count}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">PACKAGES AUDITED</span>
                <span className="font-mono text-slate-300">{latestScan.package_count}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={scanning || nodes.length === 0}
            className="w-full py-2.5 px-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-semibold shadow transition flex items-center justify-center gap-2"
          >
            {scanning ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin" />
                Querying OSV.dev Batch API...
              </>
            ) : (
              <>
                <ShieldAlert className="h-4 w-4" />
                Scan Ingested Packages with OSV
              </>
            )}
          </button>
        </div>
      </div>

      {/* PHASE 5: STRUCTURAL RISK + MITIGATION PRIORITY ENGINE */}
      <div className="rounded-xl border border-amber-500/30 bg-slate-900/80 p-6 sm:p-8 backdrop-blur shadow-2xl space-y-6">
        {/* Phase 5 Header & Proposed Decision Model Notice */}
        <div className="space-y-3 border-b border-slate-800 pb-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
                <Target className="h-6 w-6" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  Phase 5: Structural Risk & Mitigation Priority Engine
                </h2>
                <p className="text-xs text-slate-400">
                  Combine Vulnerability Severity, Graph Centrality, Reach Blast Radius, and Asset Criticality.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleAnalyzeRisk}
                disabled={analyzingRisk || nodes.length === 0 || vulnerabilities.length === 0}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white text-xs font-bold shadow-lg transition flex items-center gap-2"
              >
                {analyzingRisk ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Calculating Structural Risk...
                  </>
                ) : (
                  <>
                    <Activity className="h-4 w-4" />
                    Calculate Structural Risk & Rank Priorities
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Explicit Model Disclaimer Notice */}
          <div className="flex items-start gap-3 p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-amber-300">RippleGuard Proposed Risk Model Notice: </span>
              This calculation represents RippleGuard&apos;s proposed prioritization decision model, combining deterministic graph centrality and downstream reach with CVSS base severity. It is a proposed decision lens, NOT an established industry benchmark.
            </div>
          </div>
        </div>

        {/* Weights Configuration & Application Criticality Settings */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Configurable Risk Weights Panel (7 cols) */}
          <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-950/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <SlidersHorizontal className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-semibold text-slate-200">Configurable Risk Weights</h3>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                    isWeightValid
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-bold"
                      : "bg-red-500/10 text-red-400 border-red-500/30 font-bold animate-pulse"
                  }`}
                >
                  Sum: {(weightSum * 100).toFixed(0)}% {isWeightValid ? "✓" : "(Must = 100%)"}
                </span>
                <button
                  onClick={handleResetDefaultWeights}
                  className="text-[10px] text-slate-400 hover:text-slate-200 underline"
                >
                  Reset Defaults
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              {/* Severity Weight */}
              <div className="space-y-1.5 bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                <div className="flex justify-between">
                  <span className="text-slate-300 font-medium">Severity (CVSS)</span>
                  <span className="font-mono text-amber-400 font-bold">
                    {(riskProfile.severity_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={riskProfile.severity_weight}
                  onChange={(e) =>
                    setRiskProfile({ ...riskProfile, severity_weight: parseFloat(e.target.value) })
                  }
                  className="w-full accent-amber-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">CVSS v3/v4 base score normalized</span>
              </div>

              {/* Centrality Weight */}
              <div className="space-y-1.5 bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                <div className="flex justify-between">
                  <span className="text-slate-300 font-medium">Centrality</span>
                  <span className="font-mono text-amber-400 font-bold">
                    {(riskProfile.centrality_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={riskProfile.centrality_weight}
                  onChange={(e) =>
                    setRiskProfile({ ...riskProfile, centrality_weight: parseFloat(e.target.value) })
                  }
                  className="w-full accent-amber-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">PageRank + Betweenness Centrality</span>
              </div>

              {/* Blast Radius Weight */}
              <div className="space-y-1.5 bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                <div className="flex justify-between">
                  <span className="text-slate-300 font-medium">Blast Radius</span>
                  <span className="font-mono text-amber-400 font-bold">
                    {(riskProfile.blast_radius_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={riskProfile.blast_radius_weight}
                  onChange={(e) =>
                    setRiskProfile({ ...riskProfile, blast_radius_weight: parseFloat(e.target.value) })
                  }
                  className="w-full accent-amber-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">0.70×App Reach + 0.30×Package Reach</span>
              </div>

              {/* Application Criticality Weight */}
              <div className="space-y-1.5 bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
                <div className="flex justify-between">
                  <span className="text-slate-300 font-medium">Application Criticality</span>
                  <span className="font-mono text-amber-400 font-bold">
                    {(riskProfile.application_criticality_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={riskProfile.application_criticality_weight}
                  onChange={(e) =>
                    setRiskProfile({
                      ...riskProfile,
                      application_criticality_weight: parseFloat(e.target.value),
                    })
                  }
                  className="w-full accent-amber-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">Max criticality of affected applications</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-400">
                Formula: <code className="text-amber-300 font-mono text-[11px]">(Sev×w) + (Cent×w) + (Blast×w) + (Crit×w) × 100</code>
              </span>
              <button
                onClick={handleSaveRiskProfile}
                disabled={savingProfile || !isWeightValid}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-medium transition"
              >
                {savingProfile ? "Saving..." : "Save Risk Weights"}
              </button>
            </div>

            {profileMsg && (
              <div className="p-2 rounded bg-slate-900 border border-slate-700 text-xs text-center text-slate-300">
                {profileMsg}
              </div>
            )}
          </div>

          {/* Application Criticality Settings Panel (5 cols) */}
          <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-950/60 p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
              <Building className="h-4 w-4 text-teal-400" />
              <h3 className="text-sm font-semibold text-slate-200">Application Criticality Tiers</h3>
            </div>
            <p className="text-[11px] text-slate-400">
              Assign asset tiers to applications. Downstream dependencies propagating to critical applications inherit high impact.
            </p>

            <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
              {applications.length === 0 ? (
                <div className="text-xs text-slate-500 py-4 text-center">
                  Ingest an SBOM to discover and configure application nodes.
                </div>
              ) : (
                applications.map((app) => (
                  <div
                    key={app.application_id}
                    className="p-2.5 rounded bg-slate-900/50 border border-slate-800/80 flex items-center justify-between text-xs"
                  >
                    <div>
                      <span className="font-semibold text-white block">{app.name}</span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        Score: {app.criticality_score.toFixed(2)} ({app.criticality_source})
                      </span>
                    </div>

                    <select
                      value={app.criticality_tier}
                      onChange={(e) => handleUpdateCriticality(app.application_id, e.target.value)}
                      className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-2 py-1 text-xs focus:outline-none focus:border-teal-500"
                    >
                      <option value="CRITICAL">CRITICAL (1.00)</option>
                      <option value="HIGH">HIGH (0.75)</option>
                      <option value="MEDIUM">MEDIUM (0.50)</option>
                      <option value="LOW">LOW (0.25)</option>
                    </select>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Error notice if risk analysis failed */}
        {riskError && (
          <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{riskError}</span>
          </div>
        )}

        {/* Ranked Mitigation Priority Table */}
        {latestPriority && latestPriority.results && latestPriority.results.length > 0 && (
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Ranked Mitigation Priorities ({latestPriority.results.length})
                </h3>
              </div>
              <span className="text-[11px] text-slate-400">
                Fix the highest-leverage node, not simply the loudest CVE.
              </span>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] bg-slate-900/60 border border-slate-800/80 px-3.5 py-2 rounded-lg text-slate-400">
              <span className="font-semibold text-slate-300">Priority Bands:</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-400"></span><strong className="text-red-300">CRITICAL</strong> 75.00–100.00</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-orange-400"></span><strong className="text-orange-300">HIGH</strong> 50.00–74.99</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-400"></span><strong className="text-amber-300">MODERATE</strong> 25.00–49.99</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-blue-400"></span><strong className="text-blue-300">LOW</strong> 0.00–24.99</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-slate-500"></span><strong className="text-slate-400">UNSCORED</strong> missing CVSS</span>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Rank</th>
                    <th className="py-2.5 px-3">Package</th>
                    <th className="py-2.5 px-3">Vulnerability</th>
                    <th className="py-2.5 px-3">CVSS</th>
                    <th className="py-2.5 px-3">Centrality</th>
                    <th className="py-2.5 px-3">Reach</th>
                    <th className="py-2.5 px-3">App Criticality</th>
                    <th className="py-2.5 px-3">Ripple Risk</th>
                    <th className="py-2.5 px-3">Priority Band</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {latestPriority.results.map((r) => {
                    const bandColors: Record<string, string> = {
                      CRITICAL: "bg-red-500/20 text-red-300 border-red-500/40",
                      HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
                      MODERATE: "bg-amber-500/20 text-amber-300 border-amber-500/40",
                      LOW: "bg-blue-500/20 text-blue-300 border-blue-500/40",
                      UNSCORED: "bg-slate-800 text-slate-400 border-slate-700",
                    };

                    return (
                      <tr key={r.id} className="hover:bg-slate-800/40 transition">
                        {/* Rank */}
                        <td className="py-2 px-3">
                          {r.priority_rank !== null && r.priority_rank !== undefined ? (
                            <span
                              className={`inline-flex items-center justify-center h-6 w-6 rounded-full font-bold text-xs ${
                                r.priority_rank === 1
                                  ? "bg-amber-500 text-slate-950"
                                  : r.priority_rank === 2
                                  ? "bg-slate-300 text-slate-950"
                                  : r.priority_rank === 3
                                  ? "bg-amber-800 text-amber-100"
                                  : "bg-slate-800 text-slate-300"
                              }`}
                            >
                              {r.priority_rank}
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-sans font-medium bg-slate-800 text-slate-400 border border-slate-700">
                              Unranked
                            </span>
                          )}
                        </td>

                        {/* Package */}
                        <td className="py-2 px-3">
                          <span className="font-semibold text-white block">
                            {r.package_name}@{r.package_version}
                          </span>
                          {r.dependency_depth !== null && (
                            <span className="text-[10px] text-slate-500 font-sans block">
                              Depth: {r.dependency_depth} hops
                            </span>
                          )}
                        </td>

                        {/* Vulnerability */}
                        <td className="py-2 px-3">
                          <span className="text-violet-400 font-semibold block">{r.vulnerability_osv_id}</span>
                          <span className="text-[10px] text-slate-400 font-sans truncate max-w-xs block" title={r.vulnerability_summary || ""}>
                            {r.vulnerability_summary || "No description"}
                          </span>
                        </td>

                        {/* CVSS */}
                        <td className="py-2 px-3">
                          {(() => {
                            const score = r.cvss_score ?? r.severity_raw_score;
                            return score !== null && score !== undefined ? (
                              <span className="font-bold text-amber-300">
                                {score.toFixed(1)}
                              </span>
                            ) : (
                              <span className="text-slate-500 italic text-[10px]">Unscored</span>
                            );
                          })()}
                        </td>

                        {/* Centrality */}
                        <td className="py-2 px-3">
                          <span className="font-semibold text-slate-200">
                            {(r.centrality_score ?? 0).toFixed(2)}
                          </span>
                          <span className="text-[10px] text-slate-500 block">
                            PR: {(r.pagerank ?? r.pagerank_score ?? 0).toFixed(2)} | BC: {(r.betweenness ?? r.betweenness_score ?? 0).toFixed(2)}
                          </span>
                        </td>

                        {/* Reach */}
                        <td className="py-2 px-3">
                          <span className="text-teal-300 block">
                            {r.affected_application_count} {r.affected_application_count === 1 ? "app" : "apps"}
                          </span>
                          <span className="text-[10px] text-slate-500 block">
                            +{r.affected_downstream_package_count} pkgs
                          </span>
                        </td>

                        {/* Application Criticality */}
                        <td className="py-2 px-3">
                          <span className="font-medium text-slate-200">
                            {r.max_application_criticality ? `${r.max_application_criticality} (${(r.application_criticality_score ?? 0).toFixed(2)})` : (r.application_criticality_score ?? 0).toFixed(2)}
                          </span>
                        </td>

                        {/* Ripple Risk Score */}
                        <td className="py-2 px-3">
                          <span className="text-base font-extrabold text-amber-400">
                            {(r.risk_score ?? 0).toFixed(1)}
                          </span>
                          <span className="text-[10px] text-slate-500"> / 100</span>
                        </td>

                        {/* Priority Band */}
                        <td className="py-2 px-3">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] font-sans font-bold border ${
                              bandColors[r.priority_band] || bandColors.UNSCORED
                            }`}
                          >
                            {r.priority_band}
                          </span>
                        </td>

                        {/* Actions */}
                        <td className="py-2 px-3 text-right">
                          <button
                            onClick={() => {
                              setSelectedModalResult(r);
                              setAiExplanation(null);
                              setAiStatus("not_generated");
                              setAiError(null);
                              fetchOrGenerateExplanation(r.id, false);
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-medium font-sans transition"
                          >
                            <HelpCircle className="h-3 w-3" />
                            Why this rank?
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* "Why This Rank?" Contribution Inspector Modal */}
      {selectedModalResult && (() => {
        const sevWeight = selectedModalResult.explanation?.metrics?.weights?.severity ?? riskProfile.severity_weight;
        const centWeight = selectedModalResult.explanation?.metrics?.weights?.centrality ?? riskProfile.centrality_weight;
        const blastWeight = selectedModalResult.explanation?.metrics?.weights?.blast_radius ?? riskProfile.blast_radius_weight;
        const critWeight = selectedModalResult.explanation?.metrics?.weights?.criticality ?? riskProfile.application_criticality_weight;

        const rawCvss = selectedModalResult.cvss_score ?? selectedModalResult.severity_raw_score ?? null;
        const sevNorm = selectedModalResult.severity_normalized ?? (rawCvss !== null ? rawCvss / 10.0 : 0.0);
        const centScore = selectedModalResult.centrality_score ?? 0.0;
        const blastScore = selectedModalResult.blast_radius_score ?? 0.0;
        const critScore = selectedModalResult.application_criticality_score ?? 0.0;

        const sevPts = selectedModalResult.explanation?.metrics?.components?.severity ?? (sevWeight * sevNorm * 100);
        const centPts = selectedModalResult.explanation?.metrics?.components?.centrality ?? (centWeight * centScore * 100);
        const blastPts = selectedModalResult.explanation?.metrics?.components?.blast_radius ?? (blastWeight * blastScore * 100);
        const critPts = selectedModalResult.explanation?.metrics?.components?.criticality ?? (critWeight * critScore * 100);
        const totalScore = selectedModalResult.risk_score ?? (sevPts + centPts + blastPts + critPts);

        const narrativeText = selectedModalResult.reason || selectedModalResult.explanation?.text || "Calculated via RippleGuard proposed risk model.";
        const fixedVersions = selectedModalResult.mitigation_evidence?.fixed_versions || selectedModalResult.mitigation_evidence?.vulnerability?.fixed_versions || [];
        const fixGuidance = selectedModalResult.mitigation_evidence?.fix_guidance || "Upgrade dependency to resolve downstream propagation risk.";
        const affectedApps = selectedModalResult.mitigation_evidence?.affected_applications || [];

        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-amber-500/40 bg-slate-900 p-6 shadow-2xl space-y-6">
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
                    <Scale className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      Priority Rank #{selectedModalResult.priority_rank ?? "—"} Explanation
                    </h3>
                    <span className="text-xs text-slate-400 font-mono">
                      {selectedModalResult.package_name}@{selectedModalResult.package_version} · {selectedModalResult.vulnerability_osv_id}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedModalResult(null)}
                  className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* SECTION 1: DETERMINISTIC ANALYSIS */}
              <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Deterministic Security Analysis (Single Source of Truth)
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">Engine: NetworkX + OSV</span>
                </div>

                {/* Total Risk Score Banner */}
                <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-amber-500/30">
                  <div>
                    <span className="text-xs text-slate-400 uppercase tracking-wider block font-semibold">
                      Computed Ripple Risk Score
                    </span>
                    <span className="text-3xl font-extrabold text-amber-400 font-mono">
                      {totalScore !== null && selectedModalResult.risk_score !== null ? totalScore.toFixed(1) : "Unscored"}
                      {selectedModalResult.risk_score !== null && <span className="text-sm font-normal text-slate-500"> / 100</span>}
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-slate-400 block">Priority Band</span>
                    <span className="text-sm font-bold text-amber-300 font-mono uppercase">
                      {selectedModalResult.priority_band}
                    </span>
                  </div>
                </div>

                {/* Component Contributions Breakdown */}
                <div className="space-y-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Metric Component Contributions
                  </h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    {/* Severity */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 font-sans block">Severity Score</span>
                      <span className="text-amber-300 font-bold block">
                        {rawCvss !== null ? `${sevPts.toFixed(1)} pts` : "Unscored"}
                      </span>
                      <span className="text-[10px] text-slate-400 block font-sans">
                        Weight: {(sevWeight * 100).toFixed(0)}%
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        CVSS: {rawCvss !== null ? rawCvss.toFixed(1) : "N/A"}
                      </span>
                    </div>

                    {/* Centrality */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 font-sans block">Centrality Score</span>
                      <span className="text-indigo-300 font-bold block">
                        {centPts.toFixed(1)} pts
                      </span>
                      <span className="text-[10px] text-slate-400 block font-sans">
                        Weight: {(centWeight * 100).toFixed(0)}%
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        Score: {centScore.toFixed(2)}
                      </span>
                    </div>

                    {/* Blast Radius */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 font-sans block">Blast Radius</span>
                      <span className="text-teal-300 font-bold block">
                        {blastPts.toFixed(1)} pts
                      </span>
                      <span className="text-[10px] text-slate-400 block font-sans">
                        Weight: {(blastWeight * 100).toFixed(0)}%
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        {selectedModalResult.affected_application_count} apps, {selectedModalResult.affected_downstream_package_count} pkgs
                      </span>
                    </div>

                    {/* App Criticality */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 font-sans block">App Criticality</span>
                      <span className="text-rose-300 font-bold block">
                        {critPts.toFixed(1)} pts
                      </span>
                      <span className="text-[10px] text-slate-400 block font-sans">
                        Weight: {(critWeight * 100).toFixed(0)}%
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        Max: {critScore.toFixed(2)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Plain English Narrative Explanation */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-1">
                  <span className="text-[10px] font-bold text-amber-300 uppercase tracking-wider block font-sans">
                    Deterministic Decision Reasoning
                  </span>
                  <p className="leading-relaxed">
                    {narrativeText}
                  </p>
                </div>

                {/* Mitigation Evidence & Affected Applications */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5">
                    <span className="font-semibold text-slate-200 block">Remediation & Fix Evidence</span>
                    {fixedVersions.length > 0 ? (
                      <div className="space-y-1">
                        <span className="text-emerald-400 text-[11px] font-mono block">
                          Fixed in: {fixedVersions.join(", ")}
                        </span>
                        <span className="text-[10px] text-slate-400 block">
                          {fixGuidance}
                        </span>
                      </div>
                    ) : (
                      <span className="text-slate-500 italic text-[11px] block">
                        No fixed version recorded in OSV advisory.
                      </span>
                    )}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5">
                    <span className="font-semibold text-slate-200 block">Affected Downstream Applications</span>
                    {affectedApps.length > 0 ? (
                      <div className="space-y-1 max-h-24 overflow-y-auto">
                        {affectedApps.map((a: any, i: number) => (
                          <div key={i} className="flex justify-between text-[11px] font-mono text-teal-300">
                            <span>{a.name}</span>
                            <span className="text-slate-400">[{a.criticality_tier}]</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 italic text-[11px] block">
                        {selectedModalResult.affected_application_count > 0
                          ? `${selectedModalResult.affected_application_count} application(s) reached downstream.`
                          : "Does not propagate to an application entrypoint."}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* SECTION 2: AI EXPLANATION */}
              <div className="space-y-4 rounded-xl border border-violet-500/30 bg-violet-950/20 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-violet-400" />
                    <span className="text-xs font-bold uppercase tracking-wider text-violet-300">
                      AI Explanation & Evidence Grounding
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Status Badge */}
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                        aiStatus === "success"
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                          : aiStatus === "generating"
                          ? "bg-violet-500/20 text-violet-300 border border-violet-500/30 animate-pulse"
                          : aiStatus === "validation_failed"
                          ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                          : aiStatus === "failed"
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                          : "bg-slate-800 text-slate-400 border border-slate-700"
                      }`}
                    >
                      {aiStatus === "success" && "Verified Explanation"}
                      {aiStatus === "generating" && "Synthesizing Evidence..."}
                      {aiStatus === "validation_failed" && "Guardrail Rejection"}
                      {aiStatus === "failed" && "AI Unavailable"}
                      {aiStatus === "not_generated" && "Not Generated"}
                    </span>

                    <button
                      onClick={() => fetchOrGenerateExplanation(selectedModalResult.id, true)}
                      disabled={aiStatus === "generating"}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold shadow transition disabled:opacity-50"
                    >
                      <Sparkles className="h-3 w-3" />
                      {aiStatus === "success" ? "Regenerate" : "Generate AI Explanation"}
                    </button>
                  </div>
                </div>

                {/* State: Generating */}
                {aiStatus === "generating" && (
                  <div className="p-6 text-center space-y-2">
                    <RefreshCw className="h-6 w-6 text-violet-400 animate-spin mx-auto" />
                    <p className="text-xs text-slate-300 font-medium">
                      Synthesizing evidence-grounded explanation from deterministic snapshot...
                    </p>
                    <p className="text-[10px] text-slate-500">
                      Querying Gemini with strict schema enforcement and zero web-hallucination guardrails.
                    </p>
                  </div>
                )}

                {/* State: Failed / Validation Failed */}
                {(aiStatus === "failed" || aiStatus === "validation_failed") && (
                  <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 space-y-1.5 text-xs">
                    <div className="flex items-center gap-2 text-rose-300 font-semibold">
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                      <span>AI explanation unavailable. Deterministic RippleGuard analysis is still available.</span>
                    </div>
                    {aiError && (
                      <p className="text-slate-400 text-[11px] pl-6 font-mono">
                        Reason: {aiError}
                      </p>
                    )}
                  </div>
                )}

                {/* State: Success */}
                {aiStatus === "success" && aiExplanation && (
                  <div className="space-y-3.5 text-xs text-slate-300 animate-in fade-in duration-150">
                    {/* Summary */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-violet-300 block">
                        Executive Summary
                      </span>
                      <p className="leading-relaxed font-sans">{aiExplanation.summary}</p>
                    </div>

                    {/* Why this priority */}
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-teal-300 block">
                        Structural Priority Rationale
                      </span>
                      <p className="leading-relaxed font-sans">{aiExplanation.why_priority}</p>
                    </div>

                    {/* Key factors */}
                    {aiExplanation.key_factors && aiExplanation.key_factors.length > 0 && (
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1.5">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300 block">
                          Key Contributing Factors
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {aiExplanation.key_factors.map((f, i) => (
                            <span key={i} className="inline-block px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200 text-[11px]">
                              • {f}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Mitigation guidance */}
                    {aiExplanation.mitigation_guidance && (
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 block">
                          Actionable Mitigation Guidance
                        </span>
                        <p className="leading-relaxed text-slate-200 font-sans">{aiExplanation.mitigation_guidance}</p>
                      </div>
                    )}

                    {/* Limitations & Model Bounds */}
                    {aiExplanation.limitations && aiExplanation.limitations.length > 0 && (
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                          Model Boundaries & Assumptions
                        </span>
                        <ul className="list-disc pl-4 space-y-0.5 text-[11px] text-slate-400">
                          {aiExplanation.limitations.map((lim, idx) => (
                            <li key={idx}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Evidence IDs Used */}
                    {aiExplanation.evidence_ids && aiExplanation.evidence_ids.length > 0 && (
                      <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-1.5">
                        <span className="text-[10px] text-slate-500 font-mono">Evidence Used:</span>
                        {aiExplanation.evidence_ids.map((eid) => (
                          <span key={eid} className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-violet-400">
                            #{eid}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="flex justify-between items-center pt-2 border-t border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">
                  {aiExplanation?.model_name ? `Model: ${aiExplanation.model_name} (Prompt v${aiExplanation.prompt_version})` : "RippleGuard Proposed Risk Lens"}
                </span>
                <button
                  onClick={() => setSelectedModalResult(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition"
                >
                  Close Inspector
                </button>
              </div>
            </div>
          </div>
        );
      })()}


      {/* PHASE 4: RIPPLE PROPAGATION ENGINE SIMULATOR */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur shadow-2xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-violet-500/20 text-violet-400 border border-violet-500/30">
              <Radio className="h-5 w-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                Phase 4: Deterministic Ripple Propagation Simulator
              </h2>
              <p className="text-xs text-slate-400">
                Traverse reverse dependency paths to answer: <span className="text-violet-300 italic">&ldquo;What happens if this dependency is compromised?&rdquo;</span>
              </p>
            </div>
          </div>

          {/* Standalone Hypothetical Compromise Trigger */}
          <div className="flex items-center gap-2">
            <select
              value={hypoSeedPkgId}
              onChange={(e) => setHypoSeedPkgId(e.target.value)}
              disabled={packageNodes.length === 0 || simulatingRipple}
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-violet-500"
            >
              <option value="">Select Package to Compromise...</option>
              {packageNodes.map((p) => {
                const dbId = p.db_id || parseInt(p.id.replace("pkg:", ""), 10);
                return (
                  <option key={p.id} value={dbId}>
                    {p.name}@{p.version}
                  </option>
                );
              })}
            </select>
            <button
              onClick={() => {
                if (hypoSeedPkgId) {
                  handleSimulateRipple(parseInt(hypoSeedPkgId, 10));
                }
              }}
              disabled={!hypoSeedPkgId || simulatingRipple}
              className="px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:bg-slate-800 disabled:text-slate-600 text-white text-xs font-semibold shadow transition flex items-center gap-1.5"
            >
              {simulatingRipple ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Radio className="h-3.5 w-3.5" />
              )}
              Simulate Compromise
            </button>
          </div>
        </div>

        {/* Status / Loading / Error */}
        {simulatingRipple && (
          <div className="flex items-center justify-center gap-3 p-6 rounded-lg border border-violet-500/30 bg-violet-950/20 text-violet-300 text-sm animate-pulse">
            <RefreshCw className="h-5 w-5 animate-spin text-violet-400" />
            <span>Simulating ripple propagation... calculating reverse impact paths across in-memory DiGraph</span>
          </div>
        )}

        {rippleError && (
          <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{rippleError}</span>
          </div>
        )}

        {/* Active Analysis View */}
        {activeRipple && (
          <div className="space-y-6">
            {/* Analysis Summary Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
              <div className="rounded-lg border border-violet-500/30 bg-violet-950/30 p-3">
                <span className="text-[10px] text-violet-300 font-medium block">COMPROMISED SEED</span>
                <span className="text-xs font-mono font-bold text-white truncate block" title={`${activeRipple.seed_package.name}@${activeRipple.seed_package.version}`}>
                  {activeRipple.seed_package.name}@{activeRipple.seed_package.version}
                </span>
                {activeRipple.seed_vulnerability && (
                  <span className="text-[10px] text-violet-400 font-mono block truncate">
                    {activeRipple.seed_vulnerability.osv_id}
                  </span>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">PROPAGATION DEPTH</span>
                <span className="text-lg font-mono font-bold text-indigo-400">
                  {activeRipple.summary.max_depth}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">AFFECTED PACKAGES</span>
                <span className="text-lg font-mono font-bold text-white">
                  {activeRipple.summary.affected_package_count}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">AFFECTED APPS</span>
                <span className="text-lg font-mono font-bold text-teal-400">
                  {activeRipple.summary.affected_application_count}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">DIRECT DEPENDENTS</span>
                <span className="text-lg font-mono font-bold text-sky-400">
                  {activeRipple.summary.direct_dependent_count}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">TRANSITIVE DEPENDENTS</span>
                <span className="text-lg font-mono font-bold text-slate-300">
                  {activeRipple.summary.transitive_dependent_count}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-[10px] text-slate-500 block">ANALYSIS STATUS</span>
                {activeRipple.summary.truncated ? (
                  <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    Truncated: {activeRipple.summary.truncation_reason}
                  </span>
                ) : (
                  <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    Complete Reach
                  </span>
                )}
              </div>
            </div>

            {/* Affected Subgraph Visualization */}
            {rippleNodes.length <= 1 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-8 text-center text-sm text-slate-400">
                This dependency has no downstream dependents. Compromise does not propagate beyond the seed node.
              </div>
            ) : (
              <RippleGraph
                nodes={rippleNodes}
                paths={ripplePaths}
                seedNodeId={String(activeRipple.seed_package.id)}
              />
            )}

            {/* Deterministic Shortest Propagation Paths */}
            {ripplePaths.length > 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <Workflow className="h-4 w-4 text-violet-400" />
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                    Deterministic Shortest Propagation Paths ({ripplePaths.length})
                  </h3>
                </div>
                <div className="space-y-2 max-h-52 overflow-y-auto pr-2 font-mono text-xs">
                  {ripplePaths.map((p) => (
                    <div
                      key={p.id}
                      className="p-2.5 rounded border border-slate-800 bg-slate-900/40 flex flex-wrap items-center gap-2 text-slate-300"
                    >
                      <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-sans">
                        Target: {p.target.name} ({p.path_length} hops)
                      </span>
                      <div className="flex items-center flex-wrap gap-1.5 text-[11px]">
                        {p.path.map((step, idx) => (
                          <React.Fragment key={idx}>
                            <span
                              className={`px-1.5 py-0.5 rounded ${
                                idx === 0
                                  ? "bg-violet-950 text-violet-300 border border-violet-700"
                                  : idx === p.path.length - 1
                                  ? step.node_type === "application"
                                    ? "bg-teal-950 text-teal-300 border border-teal-700"
                                    : "bg-indigo-950 text-indigo-300 border border-indigo-700"
                                  : "bg-slate-800 text-slate-300"
                              }`}
                            >
                              {step.name}
                            </span>
                            {idx < p.path.length - 1 && <span className="text-slate-600">→</span>}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Ripple Simulation History */}
        {rippleHistory.length > 0 && (
          <div className="border-t border-slate-800/80 pt-4 space-y-2">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-slate-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Simulation History ({rippleHistory.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/60 text-slate-500 uppercase text-[10px]">
                  <tr>
                    <th className="py-2 px-3">Run ID</th>
                    <th className="py-2 px-3">Seed Package</th>
                    <th className="py-2 px-3">Advisory</th>
                    <th className="py-2 px-3">Max Depth</th>
                    <th className="py-2 px-3">Pkgs Affected</th>
                    <th className="py-2 px-3">Apps Affected</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {rippleHistory.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-800/30">
                      <td className="py-2 px-3">#{item.id}</td>
                      <td className="py-2 px-3 text-white font-medium">
                        {item.seed_package_name}@{item.seed_package_version}
                      </td>
                      <td className="py-2 px-3 text-violet-400">{item.seed_vulnerability_osv_id || "Hypothetical"}</td>
                      <td className="py-2 px-3">{item.max_depth}</td>
                      <td className="py-2 px-3">{item.affected_package_count}</td>
                      <td className="py-2 px-3 text-teal-300">{item.affected_application_count}</td>
                      <td className="py-2 px-3">
                        <span className="text-[10px] text-emerald-400 uppercase font-sans">
                          {item.status}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={() => handleLoadPastRipple(item.id)}
                          className="text-[11px] text-violet-400 hover:text-violet-300 font-sans font-medium"
                        >
                          View Graph
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Graph Summary & Inventory Tables */}
      {graphSummary && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <span className="text-xs text-slate-400 block">APPLICATIONS</span>
              <span className="text-2xl font-bold font-mono text-blue-400">
                {graphSummary.application_count}
              </span>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <span className="text-xs text-slate-400 block">TOTAL PACKAGES</span>
              <span className="text-2xl font-bold font-mono text-slate-200">
                {graphSummary.package_count}
              </span>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <span className="text-xs text-slate-400 block">DEPENDENCY EDGES</span>
              <span className="text-2xl font-bold font-mono text-indigo-400">
                {graphSummary.dependency_count}
              </span>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <span className="text-xs text-slate-400 block">KNOWN VULNERABILITIES</span>
              <span className="text-2xl font-bold font-mono text-amber-400">
                {vulnerabilities.length}
              </span>
            </div>
          </div>

          {/* Vulnerability Intelligence Table */}
          {vulnerabilities.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 backdrop-blur space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                    Vulnerabilities from OSV ({filteredVulns.length})
                  </h3>
                </div>

                <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                  <button
                    onClick={() => setStatusFilter("all")}
                    className={`px-2.5 py-1 rounded ${statusFilter === "all" ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"}`}
                  >
                    All ({vulnerabilities.length})
                  </button>
                  <button
                    onClick={() => setStatusFilter("active")}
                    className={`px-2.5 py-1 rounded ${statusFilter === "active" ? "bg-red-950/60 text-red-300" : "text-slate-400 hover:text-slate-200"}`}
                  >
                    Active ({vulnerabilities.filter((v) => !v.is_withdrawn).length})
                  </button>
                  <button
                    onClick={() => setStatusFilter("withdrawn")}
                    className={`px-2.5 py-1 rounded ${statusFilter === "withdrawn" ? "bg-purple-950/60 text-purple-300" : "text-slate-400 hover:text-slate-200"}`}
                  >
                    Withdrawn ({vulnerabilities.filter((v) => v.is_withdrawn).length})
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950/60 text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Advisory ID</th>
                      <th className="py-2.5 px-3">Affected Package</th>
                      <th className="py-2.5 px-3">Summary</th>
                      <th className="py-2.5 px-3">Aliases</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredVulns.map((vuln) => (
                      <tr key={vuln.id} className="hover:bg-slate-800/30">
                        <td className="py-2 px-3">
                          <a
                            href={`https://osv.dev/vulnerability/${vuln.osv_id}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 underline"
                          >
                            {vuln.osv_id}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </td>
                        <td className="py-2 px-3">
                          {vuln.packages.map((p) => (
                            <span key={p.id} className="block text-white font-medium">
                              {p.name}@{p.version}
                            </span>
                          ))}
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-300 max-w-xs truncate" title={vuln.summary || ""}>
                          {vuln.summary || "No summary provided"}
                        </td>
                        <td className="py-2 px-3">
                          {vuln.aliases && vuln.aliases.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {vuln.aliases.map((a) => (
                                <span key={a} className="inline-block px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                                  {a}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          {vuln.severity_data && vuln.severity_data.length > 0 ? (
                            vuln.severity_data.map((s, idx) => (
                              <span key={idx} className="block text-[10px] text-amber-300">
                                {s.type || "CVSS"}: {s.score || "—"}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-600 text-[10px]">N/A</span>
                          )}
                        </td>
                        <td className="py-2 px-3 font-sans">
                          {vuln.is_withdrawn ? (
                            <span className="inline-block px-2 py-0.5 rounded text-[10px] font-medium bg-purple-500/20 text-purple-300 border border-purple-500/30">
                              Withdrawn
                            </span>
                          ) : (
                            <span className="inline-block px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/20 text-red-300 border border-red-500/30">
                              Active
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right">
                          {vuln.packages.map((p) => (
                            <button
                              key={p.id}
                              onClick={() => handleSimulateRipple(p.id, vuln.id)}
                              disabled={simulatingRipple}
                              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-violet-600/20 hover:bg-violet-600/30 text-violet-300 border border-violet-500/40 text-[11px] font-medium font-sans transition disabled:opacity-50"
                            >
                              <Radio className="h-3 w-3" />
                              Simulate Ripple
                            </button>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Imported Nodes Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 backdrop-blur space-y-4">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Normalized Graph Nodes ({nodes.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/60 text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Name</th>
                    <th className="py-2.5 px-3">Version</th>
                    <th className="py-2.5 px-3">Ecosystem</th>
                    <th className="py-2.5 px-3">Canonical PURL</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {nodes.map((node) => (
                    <tr key={node.id} className="hover:bg-slate-800/30">
                      <td className="py-2 px-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-sans font-medium ${
                            node.node_type === "application"
                              ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {node.node_type}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-semibold text-white">{node.name}</td>
                      <td className="py-2 px-3">{node.version || "—"}</td>
                      <td className="py-2 px-3 uppercase text-[10px]">{node.ecosystem || "—"}</td>
                      <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{node.purl || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Imported Edges Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 backdrop-blur space-y-4">
            <div className="flex items-center gap-2">
              <ArrowRight className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Dependency Edges ({edges.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/60 text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Source (Depends On)</th>
                    <th className="py-2.5 px-3">Relation</th>
                    <th className="py-2.5 px-3">Target (Dependency)</th>
                    <th className="py-2.5 px-3">Classification</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {edges.map((edge) => (
                    <tr key={edge.id} className="hover:bg-slate-800/30">
                      <td className="py-2 px-3 font-medium text-white">{edge.source_name}</td>
                      <td className="py-2 px-3 text-slate-500">→</td>
                      <td className="py-2 px-3 font-medium text-emerald-400">{edge.target_name}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-sans font-medium ${
                            edge.direct
                              ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                              : "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
                          }`}
                        >
                          {edge.direct ? "Direct" : "Transitive"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

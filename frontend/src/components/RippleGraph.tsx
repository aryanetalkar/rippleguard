"use client";

import React, { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { Layers, ShieldAlert, GitCommit, ChevronRight, Info } from "lucide-react";

export interface RippleNodeData {
  node_type: string;
  id: string;
  db_id: number;
  name: string;
  version: string | null;
  ecosystem: string | null;
  depth: number;
  is_seed: boolean;
  is_direct: boolean;
  shortest_path_length: number | null;
}

export interface RipplePathStep {
  node_type: string;
  id: string;
  db_id: number;
  name: string;
  version: string | null;
  depth: number;
}

export interface RipplePathData {
  id: number;
  target: {
    node_type: string;
    id: string;
    db_id: number;
    name: string;
    version: string | null;
  };
  path: RipplePathStep[];
  path_length: number;
}

interface RippleGraphProps {
  nodes: RippleNodeData[];
  paths: RipplePathData[];
  seedNodeId: string;
}

export default function RippleGraph({ nodes, paths, seedNodeId }: RippleGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<RippleNodeData | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Build Cytoscape elements
    const elements: cytoscape.ElementDefinition[] = [];

    // Add nodes
    nodes.forEach((node) => {
      let category = "transitive";
      if (node.is_seed) {
        category = "seed";
      } else if (node.node_type === "application") {
        category = "application";
      } else if (node.is_direct) {
        category = "direct";
      }

      const displayLabel =
        node.node_type === "application"
          ? `[APP] ${node.name}`
          : `${node.name}@${node.version || "0.0.0"}`;

      elements.push({
        group: "nodes",
        data: {
          id: node.id,
          label: displayLabel,
          category,
          depth: node.depth,
          rawNode: node,
        },
      });
    });

    // Add unique directed edges from shortest propagation paths
    const seenEdges = new Set<string>();
    paths.forEach((p) => {
      for (let i = 0; i < p.path.length - 1; i++) {
        const src = p.path[i].id;
        const tgt = p.path[i + 1].id;
        const edgeId = `${src}->${tgt}`;
        if (!seenEdges.has(edgeId)) {
          seenEdges.add(edgeId);
          elements.push({
            group: "edges",
            data: {
              id: edgeId,
              source: src,
              target: tgt,
            },
          });
        }
      }
    });

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "bottom",
            "text-margin-y": 6,
            color: "#94a3b8",
            "font-size": "10px",
            "font-family": "monospace",
            "background-color": "#334155",
            width: 28,
            height: 28,
            "border-width": 2,
            "border-color": "#475569",
          },
        },
        // Category 1: Compromised seed package (distinct purple/amber accent)
        {
          selector: "node[category = 'seed']",
          style: {
            "background-color": "#7c3aed",
            "border-color": "#c084fc",
            "border-width": 3,
            color: "#e9d5ff",
            "font-weight": "bold",
            width: 36,
            height: 36,
          },
        },
        // Category 2: Direct dependent (cyan/sky accent)
        {
          selector: "node[category = 'direct']",
          style: {
            "background-color": "#0284c7",
            "border-color": "#38bdf8",
            "border-width": 2,
            color: "#bae6fd",
            width: 30,
            height: 30,
          },
        },
        // Category 3: Transitive dependent (indigo/slate accent)
        {
          selector: "node[category = 'transitive']",
          style: {
            "background-color": "#4338ca",
            "border-color": "#818cf8",
            "border-width": 2,
            color: "#c7d2fe",
            width: 26,
            height: 26,
          },
        },
        // Category 4: Affected application (emerald/teal accent)
        {
          selector: "node[category = 'application']",
          style: {
            "background-color": "#0d9488",
            "border-color": "#2dd4bf",
            "border-width": 3,
            shape: "round-rectangle",
            color: "#99f6e4",
            "font-weight": "bold",
            width: 34,
            height: 34,
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#ffffff",
            "border-width": 4,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#475569",
            "target-arrow-color": "#64748b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 1.2,
          },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        roots: seedNodeId ? [`pkg:${seedNodeId}`, seedNodeId] : undefined,
        padding: 40,
        spacingFactor: 1.4,
        avoidOverlap: true,
      },
    });

    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      setSelectedNode(node.data("rawNode"));
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [nodes, paths, seedNodeId]);

  return (
    <div className="relative flex flex-col rounded-xl border border-slate-800 bg-slate-950/60 backdrop-blur-sm overflow-hidden shadow-2xl">
      {/* Graph Toolbar / Legend */}
      <div className="flex flex-wrap items-center justify-between border-b border-slate-800/80 bg-slate-900/60 px-4 py-3 text-xs">
        <div className="flex items-center gap-2 font-medium text-slate-300">
          <Layers className="h-4 w-4 text-indigo-400" />
          <span>Affected Subgraph (Impact Traversal)</span>
          <span className="text-[10px] text-slate-500 font-mono">
            {nodes.length} nodes · {paths.length} propagation paths
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full bg-violet-600 border border-violet-400" />
            <span className="text-slate-300 font-medium">Compromised Seed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full bg-sky-600 border border-sky-400" />
            <span className="text-slate-300">Direct Dependent</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full bg-indigo-600 border border-indigo-400" />
            <span className="text-slate-300">Transitive Dependent</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-sm bg-teal-600 border border-teal-400" />
            <span className="text-slate-300 font-medium">Downstream App</span>
          </div>
        </div>
      </div>

      {/* Graph Canvas */}
      <div className="relative w-full h-[480px]">
        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Floating Node Details Card */}
        {selectedNode ? (
          <div className="absolute top-4 right-4 z-20 w-72 rounded-lg border border-slate-700 bg-slate-900/95 p-4 shadow-xl backdrop-blur-md">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-400">
                Node Inspector
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-500 hover:text-slate-300 text-xs"
              >
                ✕
              </button>
            </div>
            <div className="space-y-1.5 text-xs">
              <div>
                <span className="text-slate-500 text-[10px] block">NAME</span>
                <span className="font-mono text-slate-100 font-medium break-all">
                  {selectedNode.name}
                  {selectedNode.version ? `@${selectedNode.version}` : ""}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <span className="text-slate-500 text-[10px] block">TYPE</span>
                  <span className="font-mono text-slate-200 capitalize">
                    {selectedNode.node_type}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">ROLE</span>
                  <span className="font-mono text-slate-200">
                    {selectedNode.is_seed
                      ? "Compromised Seed"
                      : selectedNode.is_direct
                      ? "Direct Dependent"
                      : selectedNode.node_type === "application"
                      ? "Downstream App"
                      : "Transitive Dependent"}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/80">
                <div>
                  <span className="text-slate-500 text-[10px] block">PROPAGATION DEPTH</span>
                  <span className="font-mono text-indigo-300 font-semibold">
                    {selectedNode.depth}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">SHORTEST PATH</span>
                  <span className="font-mono text-slate-300">
                    {selectedNode.shortest_path_length ?? 0} edge(s)
                  </span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="absolute bottom-3 left-4 pointer-events-none text-[11px] text-slate-500 bg-slate-950/70 px-2.5 py-1 rounded border border-slate-800/80">
            Click any node to view impact metrics and details
          </div>
        )}
      </div>
    </div>
  );
}

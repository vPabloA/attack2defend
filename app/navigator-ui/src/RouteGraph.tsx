import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';

// ── Minimal compatible types (mirror shapes from main.tsx) ─────────────────

type SlimRouteNode = {
  id: string;
  type: string;
  name: string;
  description?: string;
  url?: string;
  metadata?: Record<string, unknown>;
};

type SlimRouteEdge = {
  source: string;
  target: string;
  relationship: string;
  confidence?: string;
  source_ref?: string;
  source_kind?: string;
};

type SlimBundle = {
  nodes: SlimRouteNode[];
  edges: SlimRouteEdge[];
};

type SlimResolvedRoute = {
  root: string;
  nodes: string[];
  edges: SlimRouteEdge[];
};

// ── Graph JSON types (from graph/projection.py output) ─────────────────────

type GraphNodeData = {
  id: string;
  type: string;
  label?: string;
  title?: string;
  role?: string;
  confidence?: string;
  source_refs?: string[];
  coherence_reading?: string;
  xLayer: number;
  x: number;
  y: number;
};

type GraphEdgeData = {
  source: string;
  target: string;
  mapping_basis: string;
  rationale_es?: string;
  score?: number;
  source_refs?: string[];
};

type GraphJson = {
  canvas: { width: number; height: number };
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
};

// ── Visual constants ───────────────────────────────────────────────────────

const TYPE_FILL: Record<string, string> = {
  cve: '#dc2626', cwe: '#d97706', capec: '#7c3aed', attack: '#1d4ed8', d3fend: '#15803d',
};
const TYPE_STROKE: Record<string, string> = {
  cve: '#fca5a5', cwe: '#fde68a', capec: '#c4b5fd', attack: '#93c5fd', d3fend: '#86efac',
};
// Color coding by provenance — the core contract of the graph
const EDGE_COLOR: Record<string, string> = {
  official_explicit:   '#16a34a', // green  — NVD/MITRE explicit
  official_related:    '#64748b', // slate  — MITRE derived
  analytical_inferred: '#f59e0b', // orange — analytical inference
  conditional:         '#3b82f6', // blue   — context-dependent
  unverified:          '#ef4444', // red    — insufficient evidence
};
const EDGE_DASH: Record<string, string> = {
  official_explicit: '',
  official_related: '',
  analytical_inferred: '6 3',
  conditional: '5 4',
  unverified: '3 3',
};
const EDGE_WIDTHS: Record<string, number> = {
  official_explicit: 2.5, official_related: 1.5,
  analytical_inferred: 1.5, conditional: 1.5, unverified: 1,
};

// ── Layout constants ───────────────────────────────────────────────────────

const CCG_W = 1300;
const CCG_H = 830;
const CCG_HDR_H = 64;            // CVE header bar
const CCG_MAIN_TOP = CCG_HDR_H + 18;
const CCG_D3_LINE_Y = 618;       // horizontal separator above D3FEND row
const CCG_D3_Y = 693;            // D3FEND node y-center
const CCG_FOOTER_Y = CCG_H - 46; // edge legend row
const NODE_W = 156;
const NODE_H = 52;
const D3_NODE_W = 128;
const D3_NODE_H = 46;
const BG = '#0f172a';
const HDR_BG = '#1e293b';
const TEXT_MAIN = '#f1f5f9';
const TEXT_SUB = '#94a3b8';
// Column x-centers for layers 0–3 (CVE, CWE, CAPEC, ATT&CK)
const CCG_MAIN_COLS: Record<number, number> = { 0: 120, 1: 380, 2: 650, 3: 910 };
const TYPE_LAYER: Record<string, number> = { cve: 0, cwe: 1, capec: 2, attack: 3, d3fend: 4 };
const THREAT_TYPES = new Set(['cve', 'cwe', 'capec', 'attack', 'd3fend']);
const EDGE_BASES = ['official_explicit', 'official_related', 'analytical_inferred', 'conditional', 'unverified'];
const EDGE_LABELS: Record<string, string> = {
  official_explicit: 'Explícito oficial',
  official_related: 'Oficial relacionado',
  analytical_inferred: 'Inferencia analítica',
  conditional: 'Condicional',
  unverified: 'No verificado',
};

const LEGEND_ITEMS: Array<{ label: string; type: string }> = [
  { label: 'CVE', type: 'cve' }, { label: 'CWE', type: 'cwe' },
  { label: 'CAPEC', type: 'capec' }, { label: 'ATT&CK', type: 'attack' },
  { label: 'D3FEND', type: 'd3fend' },
];

// ── Node repositioning for Causal Chain Graph layout ──────────────────────

function repositionNodes(rawNodes: GraphNodeData[]): GraphNodeData[] {
  const byLayer: Record<number, GraphNodeData[]> = {};
  for (const n of rawNodes) {
    const l = n.xLayer ?? 0;
    if (!byLayer[l]) byLayer[l] = [];
    byLayer[l].push(n);
  }

  const result: GraphNodeData[] = [];
  const mainH = CCG_D3_LINE_Y - CCG_MAIN_TOP - 20;

  // Layers 0–3: left-to-right column layout in main graph area
  for (let layer = 0; layer <= 3; layer++) {
    const nodes = byLayer[layer] ?? [];
    const cx = CCG_MAIN_COLS[layer] ?? 120 + layer * 260;
    nodes.forEach((n, i) => {
      result.push({ ...n, x: cx, y: CCG_MAIN_TOP + (mainH / (nodes.length + 1)) * (i + 1) });
    });
  }

  // Layer 4: D3FEND — horizontal defensive timeline at bottom
  const d3nodes = byLayer[4] ?? [];
  if (d3nodes.length > 0) {
    const spread = CCG_W - 160;
    d3nodes.forEach((n, i) => {
      const x = d3nodes.length === 1
        ? CCG_W / 2
        : 80 + (spread * i) / (d3nodes.length - 1);
      result.push({ ...n, x, y: CCG_D3_Y });
    });
  }
  return result;
}

// ── Graph builder from route/bundle data (fallback) ────────────────────────

function confidenceToBasis(confidence?: string, sourceKind?: string): string {
  if (sourceKind === 'official') return 'official_explicit';
  // 'curated' means analytically reviewed — not an official MITRE explicit mapping
  if (sourceKind === 'curated') return 'official_related';
  if (confidence === 'high') return 'official_related';
  if (confidence === 'medium') return 'analytical_inferred';
  if (confidence === 'low') return 'conditional';
  return 'analytical_inferred';
}

function buildGraphFromRoute(bundle: SlimBundle, route: SlimResolvedRoute): GraphJson {
  const nodeMap = new Map(bundle.nodes.map((n) => [n.id, n]));
  const routeNodes = route.nodes
    .map((id) => nodeMap.get(id))
    .filter((n): n is SlimRouteNode => Boolean(n && THREAT_TYPES.has(n.type)));

  const byLayer: Record<number, SlimRouteNode[]> = {};
  for (const node of routeNodes) {
    const layer = TYPE_LAYER[node.type] ?? 0;
    if (!byLayer[layer]) byLayer[layer] = [];
    byLayer[layer].push(node);
  }

  const mainH = CCG_D3_LINE_Y - CCG_MAIN_TOP - 20;
  const graphNodes: GraphNodeData[] = [];

  // Layers 0–3
  for (let layer = 0; layer <= 3; layer++) {
    const nodes = byLayer[layer] ?? [];
    const cx = CCG_MAIN_COLS[layer] ?? 120 + layer * 260;
    nodes.forEach((node, i) => {
      graphNodes.push({
        id: node.id, type: node.type, label: node.id, title: node.name,
        role: i === 0 ? 'primary' : 'secondary', confidence: 'unknown',
        xLayer: layer,
        x: cx,
        y: CCG_MAIN_TOP + (mainH / (nodes.length + 1)) * (i + 1),
      });
    });
  }

  // D3FEND timeline
  const d3nodes = byLayer[4] ?? [];
  const spread = CCG_W - 160;
  d3nodes.forEach((node, i) => {
    graphNodes.push({
      id: node.id, type: node.type, label: node.id, title: node.name,
      role: 'defensive', confidence: 'unknown', xLayer: 4,
      x: d3nodes.length === 1 ? CCG_W / 2 : 80 + (spread * i) / (d3nodes.length - 1),
      y: CCG_D3_Y,
    });
  });

  const nodeIds = new Set(graphNodes.map((n) => n.id));
  const graphEdges: GraphEdgeData[] = route.edges
    .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map((e) => ({
      source: e.source, target: e.target,
      mapping_basis: confidenceToBasis(e.confidence, e.source_kind),
      rationale_es: e.relationship,
    }));

  return { canvas: { width: CCG_W, height: CCG_H }, nodes: graphNodes, edges: graphEdges };
}

// ── Export helpers ─────────────────────────────────────────────────────────

function triggerDownload(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function buildMermaid(nodes: GraphNodeData[], edges: GraphEdgeData[]): string {
  const lines = ['flowchart LR'];
  nodes.forEach((n) => {
    const safe = n.id.replace(/[^a-zA-Z0-9_]/g, '_');
    const name = (n.title || n.id).replace(/"/g, "'").slice(0, 28);
    lines.push(`  ${safe}["${n.id}\\n${name}"]`);
  });
  edges.forEach((e) => {
    const src = e.source.replace(/[^a-zA-Z0-9_]/g, '_');
    const tgt = e.target.replace(/[^a-zA-Z0-9_]/g, '_');
    const arrow = (e.mapping_basis === 'official_explicit' || e.mapping_basis === 'official_related') ? '-->' : '-.->';
    lines.push(`  ${src} ${arrow} ${tgt}`);
  });
  nodes.forEach((n) => {
    const safe = n.id.replace(/[^a-zA-Z0-9_]/g, '_');
    lines.push(`  style ${safe} fill:${TYPE_FILL[n.type] || '#64748b'},color:#fff`);
  });
  return lines.join('\n');
}

// ── SummaryCard — top 3 D3FEND countermeasures ────────────────────────────

function SummaryCard({ nodes }: { nodes: GraphNodeData[] }) {
  const top3 = nodes.filter((n) => n.type === 'd3fend').slice(0, 3);
  if (top3.length === 0) return null;
  return (
    <div style={{
      position: 'absolute', top: 12, right: 12, width: 220, zIndex: 20,
      background: 'rgba(15,23,42,0.92)', border: '1px solid #1e3a5f',
      borderRadius: 10, padding: '10px 14px', backdropFilter: 'blur(4px)',
    }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: '#16a34a', letterSpacing: '0.08em', marginBottom: 6 }}>
        🛡 DEFENSAS PRIORITARIAS
      </div>
      {top3.map((n, i) => (
        <div key={n.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6 }}>
          <span style={{
            minWidth: 18, height: 18, borderRadius: '50%', background: '#15803d',
            color: '#fff', fontSize: 10, fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>{i + 1}</span>
          <div>
            <div style={{ color: '#86efac', fontSize: 11, fontWeight: 700 }}>{n.id}</div>
            <div style={{ color: '#94a3b8', fontSize: 10, lineHeight: 1.4 }}>
              {(n.title || '').slice(0, 40)}{(n.title || '').length > 40 ? '…' : ''}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── SidePanel — per-node detail panel on click ────────────────────────────

const BASIS_BADGE: Record<string, { color: string; label: string }> = {
  official_explicit:   { color: '#16a34a', label: 'Explícito oficial' },
  official_related:    { color: '#475569', label: 'Oficial relacionado' },
  analytical_inferred: { color: '#b45309', label: 'Inferencia analítica' },
  conditional:         { color: '#1d4ed8', label: 'Condicional' },
  unverified:          { color: '#dc2626', label: 'No verificado' },
};

function SidePanel({
  node,
  edges,
  nodeMap,
  onClose,
}: {
  node: GraphNodeData;
  edges: GraphEdgeData[];
  nodeMap: Map<string, GraphNodeData>;
  onClose: () => void;
}) {
  const incoming = edges.filter((e) => e.target === node.id);
  const outgoing = edges.filter((e) => e.source === node.id);
  const fill = TYPE_FILL[node.type] || '#475569';
  const basis = incoming[0]?.mapping_basis ?? 'unverified';
  const badge = BASIS_BADGE[basis] ?? { color: '#475569', label: basis };

  return (
    <div style={{
      position: 'absolute', top: 0, right: 0, width: 280, height: '100%',
      background: '#0f172a', borderLeft: '1px solid #1e3a5f',
      display: 'flex', flexDirection: 'column', zIndex: 30, overflowY: 'auto',
    }}>
      {/* Header */}
      <div style={{ background: fill, padding: '14px 16px 10px', position: 'relative' }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute', top: 8, right: 10, background: 'none',
            border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: 18,
          }}
        >×</button>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#fff', marginBottom: 2 }}>{node.id}</div>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.75)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          {node.type} · {node.role ?? 'nodo'}
        </div>
      </div>

      <div style={{ padding: '12px 14px', flex: 1 }}>
        {/* Name */}
        {node.title && (
          <div style={{ fontSize: 12, color: TEXT_MAIN, marginBottom: 10, lineHeight: 1.5 }}>
            {node.title}
          </div>
        )}

        {/* Provenance badge */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 9, color: TEXT_SUB, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
            Provenance
          </div>
          <span style={{
            display: 'inline-block', background: badge.color + '22',
            color: badge.color, border: `1px solid ${badge.color}55`,
            borderRadius: 4, padding: '2px 7px', fontSize: 10, fontWeight: 600,
          }}>
            {badge.label}
          </span>
          {node.confidence && node.confidence !== 'unknown' && (
            <span style={{ marginLeft: 6, color: TEXT_SUB, fontSize: 10 }}>
              confianza: {node.confidence}
            </span>
          )}
        </div>

        {/* Source refs */}
        {incoming[0]?.source_refs && incoming[0].source_refs.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 9, color: TEXT_SUB, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
              Fuentes
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {incoming[0].source_refs.map((r) => (
                <span key={r} style={{
                  background: '#1e293b', color: '#94a3b8',
                  borderRadius: 4, padding: '2px 6px', fontSize: 10,
                }}>
                  {r}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Rationale */}
        {incoming[0]?.rationale_es && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 9, color: TEXT_SUB, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
              Rationale
            </div>
            <div style={{ fontSize: 11, color: '#cbd5e1', lineHeight: 1.55 }}>
              {incoming[0].rationale_es}
            </div>
          </div>
        )}

        {/* Coherence reading */}
        {node.coherence_reading && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 9, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
              Lectura de coherencia
            </div>
            <div style={{ fontSize: 11, color: '#e2e8f0', lineHeight: 1.6, background: '#1e293b', borderRadius: 6, padding: '8px 10px' }}>
              {node.coherence_reading}
            </div>
          </div>
        )}

        {/* Connections */}
        {(outgoing.length > 0) && (
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 9, color: TEXT_SUB, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
              Conecta con →
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {outgoing.map((e) => {
                const tgt = nodeMap.get(e.target);
                const c = EDGE_COLOR[e.mapping_basis] || '#64748b';
                return (
                  <div key={e.target} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: c, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: TYPE_STROKE[tgt?.type ?? ''] || '#94a3b8', fontWeight: 600 }}>
                      {e.target}
                    </span>
                    <span style={{ fontSize: 9, color: '#475569' }}>{tgt?.title?.slice(0, 24) ?? ''}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── RouteGraph — Causal Chain Graph SVG component ─────────────────────────

function RouteGraph({ graph, inputId }: { graph: GraphJson; inputId: string }) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [tx, setTx] = useState(0);
  const [ty, setTy] = useState(0);
  const [scale, setScale] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const dragging = useRef<{ startX: number; startY: number; origTx: number; origTy: number } | null>(null);

  const { nodes: rawNodes, edges } = graph;

  // Reposition all nodes according to the Causal Chain Graph layout
  const nodes = useMemo(() => repositionNodes(rawNodes), [rawNodes]);
  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const selectedNode = selected ? nodeMap.get(selected) ?? null : null;

  const connectedNodeIds: Set<string> | null = selected
    ? new Set([selected,
        ...edges.filter((e) => e.source === selected).map((e) => e.target),
        ...edges.filter((e) => e.target === selected).map((e) => e.source)])
    : null;
  const connectedEdgeKeys: Set<string> | null = selected
    ? new Set(edges.filter((e) => e.source === selected || e.target === selected).map((e) => `${e.source}→${e.target}`))
    : null;

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.88;
    setScale((prev) => Math.max(0.25, Math.min(3.5, prev * factor)));
  }, []);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if ((e.target as Element).closest('[data-node]')) return;
    dragging.current = { startX: e.clientX, startY: e.clientY, origTx: tx, origTy: ty };
  }, [tx, ty]);

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging.current) return;
    setTx(dragging.current.origTx + (e.clientX - dragging.current.startX));
    setTy(dragging.current.origTy + (e.clientY - dragging.current.startY));
  }, []);

  const stopDrag = useCallback(() => { dragging.current = null; }, []);

  const handleNodeClick = useCallback((nodeId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelected((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  const resetView = useCallback(() => { setTx(0); setTy(0); setScale(1); }, []);

  const exportJson = useCallback(() => {
    triggerDownload(JSON.stringify(graph, null, 2), `${inputId}-graph.json`, 'application/json');
  }, [graph, inputId]);
  const exportMermaid = useCallback(() => {
    triggerDownload(buildMermaid(nodes, edges), `${inputId}-graph.mmd`, 'text/plain');
  }, [nodes, edges, inputId]);
  const exportSvg = useCallback(() => {
    if (!svgRef.current) return;
    triggerDownload(new XMLSerializer().serializeToString(svgRef.current), `${inputId}-graph.svg`, 'image/svg+xml');
  }, [inputId]);

  return (
    <section className="coherence-graph-panel">
      {/* Toolbar */}
      <div className="coherence-graph-toolbar">
        <div className="coherence-graph-info">
          <strong>{inputId}</strong>
          <span>Causal Chain Graph · {nodes.length} nodos · {edges.length} aristas</span>
        </div>
        <div className="coherence-graph-actions">
          <button className="cgraph-btn" onClick={exportJson}>JSON</button>
          <button className="cgraph-btn" onClick={exportMermaid}>Mermaid</button>
          <button className="cgraph-btn" onClick={exportSvg}>SVG</button>
          <button className="cgraph-btn cgraph-btn-secondary" onClick={resetView}>Reset</button>
        </div>
      </div>

      {/* Graph canvas + overlays */}
      <div
        ref={wrapperRef}
        className="coherence-graph-wrapper"
        style={{ position: 'relative' }}
        onClick={() => setSelected(null)}
      >
        {/* Summary card (top-right) */}
        <SummaryCard nodes={nodes} />

        {/* Side panel (appears on node click) */}
        {selectedNode && (
          <SidePanel
            node={selectedNode}
            edges={edges}
            nodeMap={nodeMap}
            onClose={() => setSelected(null)}
          />
        )}

        <svg
          ref={svgRef}
          viewBox={`0 0 ${CCG_W} ${CCG_H}`}
          className="coherence-graph-svg"
          onWheel={onWheel}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={stopDrag}
          onMouseLeave={stopDrag}
          style={{ cursor: dragging.current ? 'grabbing' : 'grab' }}
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {EDGE_BASES.map((basis) => (
              <marker key={basis} id={`arrow-${basis}`}
                markerWidth="7" markerHeight="6" refX="7" refY="3" orient="auto">
                <polygon points="0 0, 7 3, 0 6" fill={EDGE_COLOR[basis] || '#64748b'} />
              </marker>
            ))}
          </defs>

          {/* Canvas background */}
          <rect width={CCG_W} height={CCG_H} fill={BG} />

          {/* ── CVE header bar ──────────────────────────────── */}
          <rect x={0} y={0} width={CCG_W} height={CCG_HDR_H} fill={HDR_BG} />
          <text x={22} y={27} fill={TYPE_STROKE['cve']} fontSize="13" fontWeight="700">{inputId}</text>
          <text x={22} y={46} fill={TEXT_SUB} fontSize="10">
            CVE → CWE → CAPEC → ATT&amp;CK → D3FEND
          </text>
          <text x={CCG_W / 2} y={27} textAnchor="middle" fill={TEXT_MAIN} fontSize="12" fontWeight="600">
            Causal Chain Graph
          </text>
          <text x={CCG_W / 2} y={45} textAnchor="middle" fill="#475569" fontSize="9">
            Verde = oficial explícito · Naranja = inferencia analítica · Azul = condicional
          </text>

          {/* Pannable/zoomable group */}
          <g transform={`translate(${tx} ${ty}) scale(${scale})`}>

            {/* ── Layer column labels ──────────────────────── */}
            {([
              [0, 'CVE'], [1, 'CWE'], [2, 'CAPEC'], [3, 'ATT&CK'],
            ] as [number, string][]).map(([layer, label]) => (
              <text
                key={layer}
                x={CCG_MAIN_COLS[layer]}
                y={CCG_MAIN_TOP - 8}
                textAnchor="middle"
                fill="#334155"
                fontSize="9"
                fontWeight="700"
                letterSpacing="0.08em"
              >
                {label}
              </text>
            ))}

            {/* ── D3FEND separator + label ─────────────────── */}
            <line x1={20} y1={CCG_D3_LINE_Y} x2={CCG_W - 20} y2={CCG_D3_LINE_Y}
              stroke="#1e3a5f" strokeWidth="1" strokeDasharray="4 4" />
            <text x={CCG_W / 2} y={CCG_D3_LINE_Y - 8} textAnchor="middle"
              fill="#1d4ed8" fontSize="9" fontWeight="700" letterSpacing="0.1em">
              D3FEND — CONTRAMEDIDAS DEFENSIVAS
            </text>

            {/* ── Edges ────────────────────────────────────── */}
            {edges.map((edge, i) => {
              const src = nodeMap.get(edge.source);
              const tgt = nodeMap.get(edge.target);
              if (!src || !tgt) return null;

              const isD3Edge = tgt.xLayer === 4;
              const basis = edge.mapping_basis || 'unverified';
              const color = EDGE_COLOR[basis] || '#64748b';
              const dash = EDGE_DASH[basis];
              const sw = EDGE_WIDTHS[basis] || 1.5;
              const isLit = !connectedEdgeKeys || connectedEdgeKeys.has(`${edge.source}→${edge.target}`);

              let d: string;
              if (isD3Edge) {
                // Vertical bezier from bottom of ATT&CK node to top of D3FEND node
                const sx = src.x;
                const sy = src.y + NODE_H / 2;
                const ex = tgt.x;
                const ey = tgt.y - D3_NODE_H / 2;
                const my = (sy + ey) / 2;
                d = `M ${sx},${sy} C ${sx},${my} ${ex},${my} ${ex},${ey}`;
              } else {
                // Horizontal bezier between same-level layers
                const sx = src.x + NODE_W / 2;
                const sy = src.y;
                const ex = tgt.x - NODE_W / 2;
                const ey = tgt.y;
                const mx = (sx + ex) / 2;
                d = `M ${sx},${sy} C ${mx},${sy} ${mx},${ey} ${ex},${ey}`;
              }

              return (
                <path key={i} d={d} fill="none" stroke={color} strokeWidth={sw}
                  strokeDasharray={dash || undefined}
                  markerEnd={`url(#arrow-${basis})`}
                  opacity={isLit ? 0.88 : 0.08}
                />
              );
            })}

            {/* ── Main nodes (layers 0–3) ──────────────────── */}
            {nodes.filter((n) => n.xLayer !== 4).map((node) => {
              const fill = TYPE_FILL[node.type] || '#475569';
              const stroke = TYPE_STROKE[node.type] || '#94a3b8';
              const isSel = selected === node.id;
              const isLit = !connectedNodeIds || connectedNodeIds.has(node.id);
              const dispName = (node.title || '');
              const short = dispName.length > 20 ? dispName.slice(0, 20) + '…' : dispName;

              return (
                <g key={node.id} opacity={isLit ? 1 : 0.2} data-node="1"
                  onClick={(e) => handleNodeClick(node.id, e)}
                  style={{ cursor: 'pointer' }}
                >
                  <rect
                    x={node.x - NODE_W / 2} y={node.y - NODE_H / 2}
                    width={NODE_W} height={NODE_H} rx={8}
                    fill={fill}
                    stroke={isSel ? '#ffffff' : stroke}
                    strokeWidth={isSel ? 2.5 : 1.2}
                  />
                  {isSel && (
                    <rect
                      x={node.x - NODE_W / 2 - 3} y={node.y - NODE_H / 2 - 3}
                      width={NODE_W + 6} height={NODE_H + 6} rx={10}
                      fill="none" stroke="rgba(255,255,255,0.35)" strokeWidth="1.5"
                    />
                  )}
                  <text x={node.x} y={node.y - 7} textAnchor="middle"
                    fill="#fff" fontSize="11" fontWeight="700"
                    style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {node.id}
                  </text>
                  {short && short !== node.id && (
                    <text x={node.x} y={node.y + 12} textAnchor="middle"
                      fill="rgba(255,255,255,0.78)" fontSize="9"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}>
                      {short}
                    </text>
                  )}
                </g>
              );
            })}

            {/* ── D3FEND timeline nodes (layer 4) ─────────── */}
            {nodes.filter((n) => n.xLayer === 4).map((node) => {
              const isSel = selected === node.id;
              const isLit = !connectedNodeIds || connectedNodeIds.has(node.id);
              const dispName = (node.title || '').slice(0, 18);

              return (
                <g key={node.id} opacity={isLit ? 1 : 0.2} data-node="1"
                  onClick={(e) => handleNodeClick(node.id, e)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Shield icon background */}
                  <rect
                    x={node.x - D3_NODE_W / 2} y={node.y - D3_NODE_H / 2}
                    width={D3_NODE_W} height={D3_NODE_H} rx={6}
                    fill="#14532d"
                    stroke={isSel ? '#86efac' : '#15803d'}
                    strokeWidth={isSel ? 2 : 1}
                  />
                  <text x={node.x} y={node.y - 5} textAnchor="middle"
                    fill="#86efac" fontSize="10" fontWeight="700"
                    style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {node.id}
                  </text>
                  {dispName && (
                    <text x={node.x} y={node.y + 10} textAnchor="middle"
                      fill="rgba(134,239,172,0.75)" fontSize="8"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}>
                      {dispName}
                    </text>
                  )}
                </g>
              );
            })}
          </g>

          {/* ── Node type legend (fixed, below D3FEND row) ── */}
          {LEGEND_ITEMS.map((item, i) => {
            const lx = (CCG_W - LEGEND_ITEMS.length * 112) / 2 + i * 112;
            return (
              <g key={item.type}>
                <rect x={lx} y={CCG_FOOTER_Y - 8} width="13" height="13" rx="3"
                  fill={TYPE_FILL[item.type]} />
                <text x={lx + 17} y={CCG_FOOTER_Y + 3} fill={TEXT_SUB} fontSize="11">
                  {item.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Edge provenance legend */}
      <div className="coherence-graph-edge-legend">
        {EDGE_BASES.map((basis) => (
          <span key={basis} className="cgraph-edge-legend-item">
            <svg width="32" height="10" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }}>
              <line x1="2" y1="5" x2="30" y2="5"
                stroke={EDGE_COLOR[basis] || '#64748b'}
                strokeWidth={EDGE_WIDTHS[basis] || 1.5}
                strokeDasharray={EDGE_DASH[basis] || undefined}
              />
            </svg>
            {EDGE_LABELS[basis] ?? basis}
          </span>
        ))}
      </div>
    </section>
  );
}

// ── RouteGraphTab: entry point used by main.tsx ───────────────────────────

export function RouteGraphTab({
  bundle,
  activeRoute,
  selectedNode,
}: {
  bundle: SlimBundle;
  activeRoute: SlimResolvedRoute | null;
  selectedNode: SlimRouteNode | null;
}) {
  const [graph, setGraph] = useState<GraphJson | null>(null);

  useEffect(() => {
    if (!activeRoute || !selectedNode) { setGraph(null); return; }
    fetch(`/artifacts/routes/${selectedNode.id}/graph.json`)
      .then((r) => (r.ok ? (r.json() as Promise<GraphJson>) : Promise.reject()))
      .then((g) => setGraph(g))
      .catch(() => setGraph(buildGraphFromRoute(bundle, activeRoute)));
  }, [bundle, activeRoute, selectedNode]);

  if (!activeRoute || !selectedNode) {
    return (
      <section className="panel">
        <p style={{ color: '#94a3b8', padding: '24px' }}>
          Selecciona un CVE, CWE, CAPEC, ATT&CK o D3FEND para visualizar la ruta.
        </p>
      </section>
    );
  }
  if (!graph) {
    return (
      <section className="panel">
        <p style={{ color: '#94a3b8', padding: '24px' }}>Construyendo grafo de coherencia…</p>
      </section>
    );
  }
  if (graph.nodes.length === 0) {
    return (
      <section className="panel">
        <p style={{ color: '#94a3b8', padding: '24px' }}>
          No hay nodos de amenaza en la ruta activa. Busca un CVE, CWE, CAPEC, T1xxx o D3-xxx.
        </p>
      </section>
    );
  }
  return <RouteGraph graph={graph} inputId={selectedNode.id} />;
}

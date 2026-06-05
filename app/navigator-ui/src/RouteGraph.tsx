import React, { useCallback, useEffect, useRef, useState } from 'react';

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
  cve: '#ef4444', cwe: '#f59e0b', capec: '#7c3aed', attack: '#2563eb', d3fend: '#16a34a',
};
const TYPE_STROKE: Record<string, string> = {
  cve: '#fca5a5', cwe: '#fde68a', capec: '#c4b5fd', attack: '#93c5fd', d3fend: '#86efac',
};
const EDGE_COLOR: Record<string, string> = {
  official_explicit: '#94a3b8', official_related: '#64748b',
  analytical_inferred: '#64748b', conditional: '#475569', unverified: '#ef4444',
};
const EDGE_DASH: Record<string, string> = {
  official_explicit: '', official_related: '',
  analytical_inferred: '6 3', conditional: '4 4', unverified: '3 3',
};
const EDGE_WIDTHS: Record<string, number> = {
  official_explicit: 2, official_related: 1.5,
  analytical_inferred: 1.5, conditional: 1.2, unverified: 1,
};

const NODE_W = 170;
const NODE_H = 52;
const BG = '#0f172a';
const TEXT_MAIN = '#f1f5f9';
const TEXT_SUB = '#94a3b8';

const CANVAS_W = 1200;
const CANVAS_H = 720;
const HEADER_H = 80;
const FOOTER_H = 50;

const XCOLUMNS: Record<number, number> = { 0: 110, 1: 320, 2: 540, 3: 755, 4: 975 };
const TYPE_LAYER: Record<string, number> = {
  cve: 0, cwe: 1, capec: 2, attack: 3, d3fend: 4,
};
const THREAT_TYPES = new Set(['cve', 'cwe', 'capec', 'attack', 'd3fend']);
const EDGE_BASES = ['official_explicit', 'official_related', 'analytical_inferred', 'conditional', 'unverified'];

const LEGEND_ITEMS: Array<{ label: string; type: string }> = [
  { label: 'CVE', type: 'cve' }, { label: 'CWE', type: 'cwe' },
  { label: 'CAPEC', type: 'capec' }, { label: 'ATT&CK', type: 'attack' },
  { label: 'D3FEND', type: 'd3fend' },
];

// ── Graph builder from route/bundle data ───────────────────────────────────

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

  const availH = CANVAS_H - HEADER_H - FOOTER_H;
  const graphNodes: GraphNodeData[] = [];
  for (const [layerStr, nodes] of Object.entries(byLayer)) {
    const layer = parseInt(layerStr, 10);
    const cx = XCOLUMNS[layer] ?? 110 + layer * 200;
    nodes.forEach((node, i) => {
      const y = HEADER_H + (availH / (nodes.length + 1)) * (i + 1);
      graphNodes.push({
        id: node.id,
        type: node.type,
        label: node.id,
        title: node.name,
        role: i === 0 ? 'primary' : 'secondary',
        confidence: 'unknown',
        xLayer: layer,
        x: cx,
        y,
      });
    });
  }

  const nodeIds = new Set(graphNodes.map((n) => n.id));
  const graphEdges: GraphEdgeData[] = route.edges
    .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map((e) => ({
      source: e.source,
      target: e.target,
      mapping_basis: confidenceToBasis(e.confidence, e.source_kind),
      rationale_es: e.relationship,
    }));

  return { canvas: { width: CANVAS_W, height: CANVAS_H }, nodes: graphNodes, edges: graphEdges };
}

// ── Export helpers ─────────────────────────────────────────────────────────

function triggerDownload(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
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
    const fill = TYPE_FILL[n.type] || '#64748b';
    lines.push(`  style ${safe} fill:${fill},color:#fff`);
  });
  return lines.join('\n');
}

// ── RouteGraph SVG component ───────────────────────────────────────────────

type TooltipState = { x: number; y: number; node: GraphNodeData } | null;

function RouteGraph({ graph, inputId }: { graph: GraphJson; inputId: string }) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [tx, setTx] = useState(0);
  const [ty, setTy] = useState(0);
  const [scale, setScale] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState>(null);
  const dragging = useRef<{ startX: number; startY: number; origTx: number; origTy: number } | null>(null);

  const { nodes, edges, canvas } = graph;
  const cw = canvas.width;
  const ch = canvas.height;

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  const connectedNodeIds: Set<string> | null = selected
    ? new Set([
        selected,
        ...edges.filter((e) => e.source === selected).map((e) => e.target),
        ...edges.filter((e) => e.target === selected).map((e) => e.source),
      ])
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
    const dx = e.clientX - dragging.current.startX;
    const dy = e.clientY - dragging.current.startY;
    setTx(dragging.current.origTx + dx);
    setTy(dragging.current.origTy + dy);
  }, []);

  const stopDrag = useCallback(() => { dragging.current = null; }, []);

  const handleNodeClick = useCallback((nodeId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelected((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  const handleNodeHover = useCallback((node: GraphNodeData, e: React.MouseEvent) => {
    const rect = wrapperRef.current?.getBoundingClientRect();
    if (!rect) return;
    setTooltip({ x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14, node });
  }, []);

  const handleNodeLeave = useCallback(() => setTooltip(null), []);

  const resetView = useCallback(() => { setTx(0); setTy(0); setScale(1); }, []);

  const exportJson = useCallback(() => {
    triggerDownload(JSON.stringify(graph, null, 2), `${inputId}-graph.json`, 'application/json');
  }, [graph, inputId]);

  const exportMermaid = useCallback(() => {
    triggerDownload(buildMermaid(nodes, edges), `${inputId}-graph.mmd`, 'text/plain');
  }, [nodes, edges, inputId]);

  const exportSvg = useCallback(() => {
    if (!svgRef.current) return;
    const str = new XMLSerializer().serializeToString(svgRef.current);
    triggerDownload(str, `${inputId}-graph.svg`, 'image/svg+xml');
  }, [inputId]);

  return (
    <section className="coherence-graph-panel">
      <div className="coherence-graph-toolbar">
        <div className="coherence-graph-info">
          <strong>{inputId}</strong>
          <span>Knowledge Graph · {nodes.length} nodos · {edges.length} aristas</span>
        </div>
        <div className="coherence-graph-actions">
          <button className="cgraph-btn" onClick={exportJson}>JSON</button>
          <button className="cgraph-btn" onClick={exportMermaid}>Mermaid</button>
          <button className="cgraph-btn" onClick={exportSvg}>SVG</button>
          <button className="cgraph-btn cgraph-btn-secondary" onClick={resetView}>Reset</button>
        </div>
      </div>

      <div
        ref={wrapperRef}
        className="coherence-graph-wrapper"
        onClick={() => { setSelected(null); setTooltip(null); }}
      >
        <svg
          ref={svgRef}
          viewBox={`0 0 ${cw} ${ch}`}
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
              <marker
                key={basis}
                id={`arrow-${basis}`}
                markerWidth="8"
                markerHeight="6"
                refX="8"
                refY="3"
                orient="auto"
              >
                <polygon
                  points="0 0, 8 3, 0 6"
                  fill={EDGE_COLOR[basis] || '#64748b'}
                />
              </marker>
            ))}
          </defs>

          {/* Background */}
          <rect width={cw} height={ch} fill={BG} />

          {/* Header */}
          <text x={cw / 2} y={24} textAnchor="middle" fill={TEXT_MAIN} fontSize="16" fontWeight="700">{inputId} Knowledge Graph</text>
          <text x={cw / 2} y={44} textAnchor="middle" fill={TEXT_SUB} fontSize="11">CVE → CWE → CAPEC → ATT&CK → D3FEND</text>
          <text x={cw / 2} y={63} textAnchor="middle" fill="#475569" fontSize="10">
            ① Mapeo explícito: CVE → CWE  |  Mapeo analítico defensible: CWE → CAPEC → ATT&CK → D3FEND
          </text>

          {/* Pannable/zoomable group */}
          <g transform={`translate(${tx} ${ty}) scale(${scale})`}>

            {/* Edges (drawn under nodes) */}
            {edges.map((edge, i) => {
              const src = nodeMap.get(edge.source);
              const tgt = nodeMap.get(edge.target);
              if (!src || !tgt) return null;

              const sx = src.x + NODE_W / 2;
              const sy = src.y;
              const ex = tgt.x - NODE_W / 2;
              const ey = tgt.y;
              const mx = (sx + ex) / 2;

              const basis = edge.mapping_basis || 'unverified';
              const color = EDGE_COLOR[basis] || '#64748b';
              const dash = EDGE_DASH[basis];
              const sw = EDGE_WIDTHS[basis] || 1.5;
              const isLit = !connectedEdgeKeys || connectedEdgeKeys.has(`${edge.source}→${edge.target}`);

              return (
                <path
                  key={i}
                  d={`M ${sx},${sy} C ${mx},${sy} ${mx},${ey} ${ex},${ey}`}
                  fill="none"
                  stroke={color}
                  strokeWidth={sw}
                  strokeDasharray={dash || undefined}
                  markerEnd={`url(#arrow-${basis})`}
                  opacity={isLit ? 0.9 : 0.1}
                />
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const fill = TYPE_FILL[node.type] || '#475569';
              const stroke = TYPE_STROKE[node.type] || '#94a3b8';
              const rx = node.x - NODE_W / 2;
              const ry = node.y - NODE_H / 2;
              const isSel = selected === node.id;
              const isLit = !connectedNodeIds || connectedNodeIds.has(node.id);
              const name = (node.title || node.label || '');
              const dispName = name.length > 22 ? name.slice(0, 22) + '…' : name;

              return (
                <g
                  key={node.id}
                  opacity={isLit ? 1 : 0.25}
                  data-node="1"
                  onClick={(e) => handleNodeClick(node.id, e)}
                  onMouseEnter={(e) => handleNodeHover(node, e)}
                  onMouseLeave={handleNodeLeave}
                  style={{ cursor: 'pointer' }}
                >
                  <rect
                    x={rx} y={ry}
                    width={NODE_W} height={NODE_H}
                    rx={8}
                    fill={fill}
                    stroke={isSel ? '#ffffff' : stroke}
                    strokeWidth={isSel ? 2.5 : 1.5}
                  />
                  <text
                    x={node.x} y={node.y - 7}
                    textAnchor="middle"
                    fill="#ffffff"
                    fontSize="11"
                    fontWeight="700"
                    style={{ pointerEvents: 'none', userSelect: 'none' }}
                  >
                    {node.id}
                  </text>
                  {dispName && dispName !== node.id && (
                    <text
                      x={node.x} y={node.y + 12}
                      textAnchor="middle"
                      fill="rgba(255,255,255,0.82)"
                      fontSize="9"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}
                    >
                      {dispName}
                    </text>
                  )}
                </g>
              );
            })}
          </g>

          {/* Legend (fixed — outside the pannable group) */}
          {LEGEND_ITEMS.map((item, i) => {
            const lx = (cw - LEGEND_ITEMS.length * 110) / 2 + i * 110;
            const ly = ch - 28;
            return (
              <g key={item.type}>
                <rect x={lx} y={ly - 8} width="14" height="14" rx="3" fill={TYPE_FILL[item.type]} />
                <text x={lx + 18} y={ly + 4} fill={TEXT_SUB} fontSize="12">{item.label}</text>
              </g>
            );
          })}
        </svg>

        {/* Floating tooltip */}
        {tooltip && (
          <div
            className="coherence-graph-tooltip"
            style={{ left: tooltip.x, top: tooltip.y }}
          >
            <strong>{tooltip.node.id}</strong>
            {tooltip.node.title && <span>{tooltip.node.title}</span>}
            <small>Tipo: {tooltip.node.type}</small>
            {tooltip.node.role && <small>Role: {tooltip.node.role}</small>}
            {tooltip.node.confidence && tooltip.node.confidence !== 'unknown' && (
              <small>Confianza: {tooltip.node.confidence}</small>
            )}
          </div>
        )}
      </div>

      {/* Edge legend */}
      <div className="coherence-graph-edge-legend">
        {EDGE_BASES.map((basis) => (
          <span key={basis} className="cgraph-edge-legend-item">
            <svg width="32" height="10" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }}>
              <line
                x1="2" y1="5" x2="30" y2="5"
                stroke={EDGE_COLOR[basis] || '#64748b'}
                strokeWidth={EDGE_WIDTHS[basis] || 1.5}
                strokeDasharray={EDGE_DASH[basis] || undefined}
              />
            </svg>
            {basis.replace(/_/g, ' ')}
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

    // Try to load a pre-generated graph.json from the artifacts folder.
    // This only works when the UI is served alongside the artifacts directory.
    fetch(`/artifacts/routes/${selectedNode.id}/graph.json`)
      .then((r) => (r.ok ? (r.json() as Promise<GraphJson>) : Promise.reject()))
      .then((g) => setGraph(g))
      .catch(() => {
        // Fall back to building graph from the active route and bundle
        setGraph(buildGraphFromRoute(bundle, activeRoute));
      });
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
          No hay nodos de amenaza (CVE/CWE/CAPEC/ATT&CK/D3FEND) en la ruta activa.
          Busca un ID de tipo CVE, CWE, CAPEC, T1xxx o D3-xxx para obtener un grafo de coherencia.
        </p>
      </section>
    );
  }

  return <RouteGraph graph={graph} inputId={selectedNode.id} />;
}

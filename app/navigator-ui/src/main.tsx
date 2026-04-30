import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import fallbackRoute from './data/log4shell.route.json';
import './styles.css';

type NodeType = 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend' | 'artifact' | 'control' | 'detection' | 'evidence' | 'gap';
type CoverageStatus = 'covered' | 'partial' | 'missing' | 'unknown' | 'not_applicable';
type TabId = 'route' | 'actions' | 'graph' | 'mitre' | 'coverage' | 'export';

type RouteNode = {
  id: string;
  type: NodeType;
  name: string;
  description?: string;
  url?: string;
  metadata?: Record<string, unknown>;
};

type RouteEdge = {
  source: string;
  target: string;
  relationship: string;
  confidence?: string;
  source_ref?: string;
};

type CoverageRecord = {
  status?: CoverageStatus;
  controls?: string[];
  detections?: string[];
  evidence?: string[];
  gaps?: string[];
  owners?: string[];
};

type RouteMetadata = {
  id: string;
  input: string;
  name: string;
  curation_status?: string;
  notes?: string;
  file?: string;
};

type KnowledgeBundle = {
  metadata: {
    contract_version?: string;
    builder_version?: string;
    generated_at?: string;
    mode?: string;
    counts?: Record<string, number>;
    warnings?: unknown[];
  };
  nodes: RouteNode[];
  edges: RouteEdge[];
  indexes?: {
    by_type?: Partial<Record<NodeType, string[]>>;
    outgoing?: Record<string, Array<{ target: string; relationship: string }>>;
    incoming?: Record<string, Array<{ source: string; relationship: string }>>;
    route_inputs?: string[];
    search?: Array<{ id: string; type: NodeType; name: string; text: string }>;
  };
  coverage?: Record<string, CoverageRecord>;
  routes?: RouteMetadata[];
};

type LegacyRouteData = {
  metadata: RouteMetadata;
  nodes: RouteNode[];
  edges: RouteEdge[];
  coverage?: Record<string, CoverageRecord>;
};

const legacyRoute = fallbackRoute as LegacyRouteData;

const fallbackBundle: KnowledgeBundle = {
  metadata: {
    contract_version: 'attack2defend.knowledge_bundle.v1',
    builder_version: 'fallback-local-route',
    mode: 'fallback_local_sample',
    counts: {
      nodes: legacyRoute.nodes.length,
      edges: legacyRoute.edges.length,
      routes: 1,
    },
  },
  nodes: legacyRoute.nodes,
  edges: legacyRoute.edges,
  coverage: legacyRoute.coverage ?? {},
  routes: [legacyRoute.metadata],
};

const typeOrder: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'artifact', 'd3fend', 'control', 'detection', 'evidence', 'gap'];
const primaryColumns: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend'];

const typeLabels: Record<NodeType, string> = {
  cve: 'CVE',
  cwe: 'CWE',
  capec: 'CAPEC',
  attack: 'ATT&CK',
  d3fend: 'D3FEND',
  artifact: 'Artifact',
  control: 'Control',
  detection: 'Detection',
  evidence: 'Evidence',
  gap: 'Gap',
};

const relationshipLabels: Record<string, string> = {
  has_weakness: 'has weakness',
  has_related_weakness: 'related weakness',
  may_enable_attack_pattern: 'may enable',
  may_map_to_attack_technique: 'maps to',
  may_lead_to_post_exploitation: 'may lead to',
  affects_artifact: 'affects',
  abuses_artifact: 'abuses',
  targets_artifact: 'targets',
  protects_artifact: 'protects',
  may_be_defended_by: 'defended by',
  may_be_detected_by: 'detected by',
  implemented_by: 'implemented by',
  enables_detection: 'enables',
  requires_evidence: 'requires',
};

function App() {
  const [bundle, setBundle] = useState<KnowledgeBundle>(fallbackBundle);
  const [bundleSource, setBundleSource] = useState<'generated' | 'fallback'>('fallback');
  const [query, setQuery] = useState<string>('CVE-2021-44228');
  const [selectedId, setSelectedId] = useState<string>('CVE-2021-44228');
  const [activeTab, setActiveTab] = useState<TabId>('route');

  useEffect(() => {
    fetch('/data/knowledge-bundle.json')
      .then((response) => {
        if (!response.ok) throw new Error(`Bundle not found: ${response.status}`);
        return response.json() as Promise<KnowledgeBundle>;
      })
      .then((nextBundle) => {
        if (Array.isArray(nextBundle.nodes) && Array.isArray(nextBundle.edges)) {
          setBundle(nextBundle);
          setBundleSource('generated');
          const preferred = nextBundle.indexes?.route_inputs?.[0] ?? nextBundle.nodes[0]?.id ?? 'CVE-2021-44228';
          setQuery(preferred);
          setSelectedId(preferred);
        }
      })
      .catch(() => {
        setBundle(fallbackBundle);
        setBundleSource('fallback');
      });
  }, []);

  const nodeMap = useMemo(() => new Map(bundle.nodes.map((node) => [node.id, node])), [bundle.nodes]);
  const selectedNode = nodeMap.get(selectedId) ?? bundle.nodes[0];
  const activeRoute = useMemo(() => resolveRoute(bundle, selectedNode?.id ?? ''), [bundle, selectedNode?.id]);
  const activeNodes = useMemo(() => activeRoute.nodes.map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[], [activeRoute.nodes, nodeMap]);
  const routeNodesByType = useMemo(() => groupNodesByType(activeNodes), [activeNodes]);
  const relatedEdges = useMemo(() => bundle.edges.filter((edge) => edge.source === selectedNode?.id || edge.target === selectedNode?.id), [bundle.edges, selectedNode?.id]);
  const suggestions = useMemo(() => buildSuggestions(bundle, query), [bundle, query]);
  const markdownExport = useMemo(() => buildMarkdownExport(bundle, activeRoute, selectedNode), [bundle, activeRoute, selectedNode]);
  const navigatorLayer = useMemo(() => buildAttackNavigatorLayer(bundle, activeRoute), [bundle, activeRoute]);
  const coverageRows = useMemo(() => buildCoverageRows(bundle, activeRoute), [bundle, activeRoute]);

  function submitSearch() {
    const candidate = query.trim().toUpperCase();
    if (!candidate) return;
    const exact = nodeMap.get(candidate);
    if (exact) {
      setSelectedId(exact.id);
      return;
    }
    const fuzzy = bundle.nodes.find((node) => `${node.id} ${node.name}`.toLowerCase().includes(query.trim().toLowerCase()));
    if (fuzzy) setSelectedId(fuzzy.id);
  }

  if (!selectedNode) return <main className="app-shell"><section className="panel">No knowledge bundle loaded.</section></main>;

  return (
    <main className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Attack2Defend Navigator · MVP Pro</p>
          <h1>Threat-defense route navigator</h1>
          <p className="hero-copy">Navigate CVE, CWE, CAPEC, ATT&CK, artifacts, D3FEND, controls, detections, evidence and gaps from one local knowledge bundle.</p>
          <div className="metric-row">
            <Metric label="Nodes" value={String(bundle.nodes.length)} />
            <Metric label="Edges" value={String(bundle.edges.length)} />
            <Metric label="Routes" value={String(bundle.routes?.length ?? bundle.indexes?.route_inputs?.length ?? 1)} />
            <Metric label="Source" value={bundleSource === 'generated' ? 'Generated bundle' : 'Fallback sample'} />
          </div>
        </div>
        <div className="search-card">
          <label htmlFor="route-search">Search any ID or name</label>
          <div className="search-inline">
            <input id="route-search" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && submitSearch()} placeholder="CVE-2021-44228, T1567, CWE-79, D3-MFA..." />
            <button onClick={submitSearch}>Resolve</button>
          </div>
          <div className="suggestions">
            {suggestions.map((node) => (
              <button key={node.id} onClick={() => { setSelectedId(node.id); setQuery(node.id); }}>
                <strong>{node.id}</strong><span>{node.name}</span>
              </button>
            ))}
          </div>
        </div>
      </header>

      <nav className="tabs" aria-label="Navigator tabs">
        {[
          ['route', 'Route'],
          ['actions', 'Actions'],
          ['graph', 'Graph'],
          ['mitre', 'MITRE Views'],
          ['coverage', 'Coverage'],
          ['export', 'Export'],
        ].map(([id, label]) => (
          <button key={id} className={activeTab === id ? 'active' : ''} onClick={() => setActiveTab(id as TabId)}>{label}</button>
        ))}
      </nav>

      {activeTab === 'route' && (
        <section className="grid route-layout">
          <div className="panel wide">
            <PanelTitle title="Framework Route" subtitle="Route-first navigation across public frameworks and internal operational objects." />
            <RouteColumns nodesByType={routeNodesByType} selectedId={selectedNode.id} onSelect={setSelectedId} />
          </div>
          <NodeDetail node={selectedNode} relatedEdges={relatedEdges} onSelect={setSelectedId} nodeMap={nodeMap} />
          <RouteAnalystPreview node={selectedNode} activeRoute={activeRoute} coverageRows={coverageRows} />
        </section>
      )}

      {activeTab === 'actions' && <ActionsTab node={selectedNode} activeRoute={activeRoute} coverageRows={coverageRows} />}
      {activeTab === 'graph' && <GraphTab bundle={bundle} activeRoute={activeRoute} selectedId={selectedNode.id} setSelectedId={setSelectedId} />}
      {activeTab === 'mitre' && <MitreViewsTab bundle={bundle} activeRoute={activeRoute} navigatorLayer={navigatorLayer} />}
      {activeTab === 'coverage' && <CoverageTab rows={coverageRows} bundle={bundle} activeRoute={activeRoute} />}
      {activeTab === 'export' && <ExportTab markdown={markdownExport} json={JSON.stringify({ route: activeRoute, selected: selectedNode, coverage: coverageRows }, null, 2)} navigatorLayer={JSON.stringify(navigatorLayer, null, 2)} />}
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function PanelTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return <div className="panel-title"><h2>{title}</h2><p>{subtitle}</p></div>;
}

function RouteColumns({ nodesByType, selectedId, onSelect }: { nodesByType: Map<NodeType, RouteNode[]>; selectedId: string; onSelect: (id: string) => void }) {
  return (
    <div className="columns pro-columns">
      {primaryColumns.map((type) => (
        <div key={type} className="framework-column">
          <h3>{typeLabels[type]}</h3>
          {(nodesByType.get(type) ?? []).map((node) => (
            <button key={node.id} className={`node-pill ${node.type} ${selectedId === node.id ? 'selected' : ''}`} onClick={() => onSelect(node.id)}>
              <strong>{node.id}</strong><span>{node.name}</span>
            </button>
          ))}
          {(nodesByType.get(type) ?? []).length === 0 && <p className="empty-column">No nodes in active route.</p>}
        </div>
      ))}
    </div>
  );
}

function NodeDetail({ node, relatedEdges, onSelect, nodeMap }: { node: RouteNode; relatedEdges: RouteEdge[]; onSelect: (id: string) => void; nodeMap: Map<string, RouteNode> }) {
  return (
    <aside className="panel">
      <PanelTitle title="Selected Node" subtitle="Official meaning, direct relationships and source confidence." />
      <div className={`detail-badge ${node.type}`}>{typeLabels[node.type]}</div>
      <h3>{node.id}</h3>
      <p className="node-name">{node.name}</p>
      {node.url && <a href={node.url} target="_blank" rel="noreferrer">Open official reference</a>}
      <h4>Direct relationships</h4>
      <ul className="edge-list compact">
        {relatedEdges.length === 0 && <li>No direct edges found for current input.</li>}
        {relatedEdges.map((edge) => {
          const otherId = edge.source === node.id ? edge.target : edge.source;
          const otherNode = nodeMap.get(otherId);
          return (
            <li key={`${edge.source}-${edge.relationship}-${edge.target}`}>
              <button className="edge-button" onClick={() => onSelect(otherId)}>
                <code>{edge.source}</code> <span>{relationshipLabels[edge.relationship] ?? edge.relationship}</span> <code>{edge.target}</code>
                {otherNode && <em>{otherNode.name}</em>}
              </button>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}

function RouteAnalystPreview({ node, activeRoute, coverageRows }: { node: RouteNode; activeRoute: ResolvedRoute; coverageRows: CoverageRow[] }) {
  const missing = coverageRows.filter((row) => row.status !== 'covered').slice(0, 3);
  return (
    <aside className="panel analyst-card">
      <PanelTitle title="AI Route Analyst Pending" subtitle="Everything here is deterministic. Agentic analysis is the only pending capability." />
      <p><strong>{node.id}</strong> is connected to {activeRoute.nodes.length} nodes and {activeRoute.edges.length} relationships.</p>
      <p>The current MVP already resolves route, artifacts, D3FEND, controls, detections, evidence and coverage from the local knowledge bundle.</p>
      <div className="decision-card"><span>Recommended deterministic posture</span><strong>{missing.length ? 'VALIDATE + CLOSE GAPS' : 'MONITOR + VERIFY'}</strong></div>
    </aside>
  );
}

function ActionsTab({ node, activeRoute, coverageRows }: { node: RouteNode; activeRoute: ResolvedRoute; coverageRows: CoverageRow[] }) {
  return (
    <section className="grid two-col">
      <ActionPanel title="CTI Actions" items={buildCtiActions(node, activeRoute)} />
      <ActionPanel title="Threat Hunting Hypotheses" items={buildHuntingActions(node, activeRoute)} />
      <ActionPanel title="SOC / Detection Actions" items={buildSocActions(activeRoute, coverageRows)} />
      <ActionPanel title="Engineering / Owner Actions" items={buildOwnerActions(coverageRows)} />
    </section>
  );
}

function ActionPanel({ title, items }: { title: string; items: string[] }) {
  return <section className="panel"><PanelTitle title={title} subtitle="Deterministic action card from the current route." /><ul className="action-list">{items.map((item) => <li key={item}>{item}</li>)}</ul></section>;
}

function GraphTab({ bundle, activeRoute, selectedId, setSelectedId }: { bundle: KnowledgeBundle; activeRoute: ResolvedRoute; selectedId: string; setSelectedId: (id: string) => void }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const graphNodes = activeRoute.nodes.map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[];
  return (
    <section className="panel">
      <PanelTitle title="Route Graph" subtitle="Generated from the active route. Still simple: no graph database required." />
      <div className="graph-grid-pro">
        {graphNodes.map((node) => (
          <button key={node.id} className={`graph-node ${node.type} ${selectedId === node.id ? 'selected' : ''}`} onClick={() => setSelectedId(node.id)}>
            <strong>{node.id}</strong><span>{node.name}</span><small>{typeLabels[node.type]}</small>
          </button>
        ))}
      </div>
      <div className="relationship-strip">
        {activeRoute.edges.slice(0, 24).map((edge) => <span key={`${edge.source}-${edge.relationship}-${edge.target}`}><code>{edge.source}</code> {relationshipLabels[edge.relationship] ?? edge.relationship} <code>{edge.target}</code></span>)}
      </div>
    </section>
  );
}

function MitreViewsTab({ bundle, activeRoute, navigatorLayer }: { bundle: KnowledgeBundle; activeRoute: ResolvedRoute; navigatorLayer: unknown }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const attackNodes = activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => node?.type === 'attack');
  const d3fendNodes = activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => node?.type === 'd3fend');
  return (
    <section className="grid two-col">
      <section className="panel"><PanelTitle title="ATT&CK Native Links" subtitle="Deep links now; Navigator layer export included below." /><LinkList nodes={attackNodes} /></section>
      <section className="panel"><PanelTitle title="D3FEND Native Links" subtitle="Deep links now; CAD-compatible export remains a future adapter." /><LinkList nodes={d3fendNodes} /></section>
      <section className="panel wide"><PanelTitle title="ATT&CK Navigator Layer Preview" subtitle="Generated from selected ATT&CK techniques." /><textarea value={JSON.stringify(navigatorLayer, null, 2)} readOnly /></section>
    </section>
  );
}

function LinkList({ nodes }: { nodes: RouteNode[] }) {
  return <ul className="link-list">{nodes.length === 0 && <li>No nodes in active route.</li>}{nodes.map((node) => <li key={node.id}>{node.url ? <a href={node.url} target="_blank" rel="noreferrer">{node.id} · {node.name}</a> : `${node.id} · ${node.name}`}</li>)}</ul>;
}

function CoverageTab({ rows, bundle, activeRoute }: { rows: CoverageRow[]; bundle: KnowledgeBundle; activeRoute: ResolvedRoute }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  return (
    <section className="panel">
      <PanelTitle title="Coverage" subtitle="Curated internal coverage. Generated from route coverage, controls, detections and evidence relationships." />
      <div className="coverage-table">
        {rows.map((row) => <CoverageRowCard key={row.id} row={row} node={nodeMap.get(row.id)} />)}
        {rows.length === 0 && <p>No coverage records for this active route yet.</p>}
      </div>
    </section>
  );
}

function CoverageRowCard({ row, node }: { row: CoverageRow; node?: RouteNode }) {
  return <div className="coverage-row"><span className={`status ${row.status}`}>{row.status}</span><strong>{row.id}{node ? ` · ${node.name}` : ''}</strong><span>{row.owners.join(', ') || 'Unassigned'}</span><p>{[...row.controls, ...row.detections, ...row.evidence, ...row.gaps].slice(0, 5).join(' · ') || 'No mapped evidence yet.'}</p></div>;
}

function ExportTab({ markdown, json, navigatorLayer }: { markdown: string; json: string; navigatorLayer: string }) {
  return (
    <section className="grid two-col">
      <section className="panel"><PanelTitle title="Markdown Export" subtitle="Ready for CTI/TH/SOC notes." /><textarea value={markdown} readOnly /></section>
      <section className="panel"><PanelTitle title="Route JSON Export" subtitle="Active route and coverage." /><textarea value={json} readOnly /></section>
      <section className="panel wide"><PanelTitle title="ATT&CK Navigator Layer Export" subtitle="Use as a starter layer in ATT&CK Navigator." /><textarea value={navigatorLayer} readOnly /></section>
    </section>
  );
}

type ResolvedRoute = { root: string; nodes: string[]; edges: RouteEdge[] };
type CoverageRow = { id: string; status: CoverageStatus; controls: string[]; detections: string[]; evidence: string[]; gaps: string[]; owners: string[] };

function resolveRoute(bundle: KnowledgeBundle, root: string): ResolvedRoute {
  const start = root.toUpperCase();
  const queue: Array<{ id: string; depth: number }> = [{ id: start, depth: 0 }];
  const visited = new Set<string>([start]);
  const routeEdges: RouteEdge[] = [];
  while (queue.length) {
    const current = queue.shift();
    if (!current || current.depth >= 5) continue;
    const edges = bundle.edges.filter((edge) => edge.source === current.id || edge.target === current.id);
    for (const edge of edges) {
      routeEdges.push(edge);
      const next = edge.source === current.id ? edge.target : edge.source;
      if (!visited.has(next)) {
        visited.add(next);
        queue.push({ id: next, depth: current.depth + 1 });
      }
    }
  }
  return { root: start, nodes: Array.from(visited), edges: dedupeEdges(routeEdges) };
}

function dedupeEdges(edges: RouteEdge[]) {
  const seen = new Set<string>();
  return edges.filter((edge) => {
    const key = `${edge.source}|${edge.relationship}|${edge.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function groupNodesByType(nodes: RouteNode[]) {
  const grouped = new Map<NodeType, RouteNode[]>();
  for (const type of typeOrder) grouped.set(type, []);
  for (const node of nodes) grouped.set(node.type, [...(grouped.get(node.type) ?? []), node]);
  return grouped;
}

function buildSuggestions(bundle: KnowledgeBundle, query: string) {
  const term = query.trim().toLowerCase();
  const candidates = term ? bundle.nodes.filter((node) => `${node.id} ${node.name}`.toLowerCase().includes(term)) : bundle.nodes;
  return candidates.slice(0, 8);
}

function buildCoverageRows(bundle: KnowledgeBundle, route: ResolvedRoute): CoverageRow[] {
  const rows: CoverageRow[] = [];
  const coverage = bundle.coverage ?? {};
  for (const id of route.nodes) {
    const record = coverage[id];
    if (!record) continue;
    rows.push({ id, status: record.status ?? 'unknown', controls: record.controls ?? [], detections: record.detections ?? [], evidence: record.evidence ?? [], gaps: record.gaps ?? [], owners: record.owners ?? [] });
  }
  const relationshipRows = route.nodes.filter((id) => ['CTRL-', 'DET-', 'EV-'].some((prefix) => id.startsWith(prefix))).map((id) => ({ id, status: 'unknown' as CoverageStatus, controls: id.startsWith('CTRL-') ? [id] : [], detections: id.startsWith('DET-') ? [id] : [], evidence: id.startsWith('EV-') ? [id] : [], gaps: [], owners: [] }));
  return [...rows, ...relationshipRows].filter((row, index, all) => all.findIndex((item) => item.id === row.id) === index);
}

function buildCtiActions(node: RouteNode, route: ResolvedRoute) {
  return [
    `Create a watchlist for ${node.id} and directly related techniques/artifacts.`,
    'Track exploitability, KEV status, vendor advisories and exposed assets before assigning priority.',
    `Summarize ATT&CK techniques in route: ${route.nodes.filter((id) => id.startsWith('T')).join(', ') || 'none'}.`,
  ];
}

function buildHuntingActions(node: RouteNode, route: ResolvedRoute) {
  return [
    `Hunt for telemetry touching ${node.id} and its affected artifacts.`,
    'Correlate inbound trigger, affected asset, outbound communication, process behavior and identity/session changes.',
    `Use evidence nodes as data-source requirements: ${route.nodes.filter((id) => id.startsWith('EV-')).join(', ') || 'no evidence nodes mapped yet'}.`,
  ];
}

function buildSocActions(route: ResolvedRoute, coverageRows: CoverageRow[]) {
  const detections = coverageRows.flatMap((row) => row.detections);
  return [
    `Review or create detections: ${detections.length ? detections.join(', ') : 'no detections mapped yet'}.`,
    'Escalate if route evidence confirms exploitation, post-exploitation, credential access or exfiltration.',
    'Declare telemetry gaps explicitly instead of closing the item as covered.',
  ];
}

function buildOwnerActions(coverageRows: CoverageRow[]) {
  const owners = sortedUnique(coverageRows.flatMap((row) => row.owners));
  const gaps = coverageRows.flatMap((row) => row.gaps);
  return [
    `Assign owners: ${owners.length ? owners.join(', ') : 'owner missing'}.`,
    `Close gaps: ${gaps.length ? gaps.join('; ') : 'no curated gaps in active route'}.`,
    'Validate closure with evidence, not ticket status alone.',
  ];
}

function buildAttackNavigatorLayer(bundle: KnowledgeBundle, route: ResolvedRoute) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  return {
    name: `Attack2Defend layer - ${route.root}`,
    versions: { attack: 'unknown', navigator: '4.9.1', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Generated starter layer from Attack2Defend active route.',
    techniques: route.nodes
      .map((id) => nodeMap.get(id))
      .filter((node): node is RouteNode => Boolean(node && node.type === 'attack'))
      .map((node) => ({ techniqueID: node.id, score: 1, comment: node.name })),
  };
}

function buildMarkdownExport(bundle: KnowledgeBundle, route: ResolvedRoute, selectedNode: RouteNode) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const nodesByType = groupNodesByType(route.nodes.map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[]);
  const coverageRows = buildCoverageRows(bundle, route);
  return `# Attack2Defend Route: ${selectedNode.id} - ${selectedNode.name}

## Route

${typeOrder.map((type) => {
  const nodes = nodesByType.get(type) ?? [];
  if (!nodes.length) return '';
  return `### ${typeLabels[type]}\n${nodes.map((node) => `- ${node.id} - ${node.name}`).join('\n')}`;
}).filter(Boolean).join('\n\n')}

## Relationships
${route.edges.map((edge) => `- ${edge.source} ${relationshipLabels[edge.relationship] ?? edge.relationship} ${edge.target}`).join('\n')}

## Deterministic Actions
${buildCtiActions(selectedNode, route).concat(buildHuntingActions(selectedNode, route)).concat(buildSocActions(route, coverageRows)).map((item) => `- ${item}`).join('\n')}

## Coverage / Gaps
${coverageRows.map((row) => `- ${row.id}: ${row.status}${row.gaps.length ? ` | gaps: ${row.gaps.join('; ')}` : ''}`).join('\n') || '- No coverage records mapped yet.'}
`;
}

function sortedUnique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

createRoot(document.getElementById('root')!).render(<App />);

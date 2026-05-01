import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import fallbackRoute from './data/log4shell.route.json';
import './styles.css';

type NodeType = 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend' | 'artifact' | 'control' | 'detection' | 'evidence' | 'gap';
type CoverageStatus = 'covered' | 'partial' | 'missing' | 'unknown' | 'not_applicable';
type TabId = 'route' | 'attack' | 'd3fend' | 'coverage' | 'export';
type BundleSource = 'generated' | 'fallback';

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
    public_sources?: unknown[];
    public_source_failures?: unknown[];
    seed_inputs?: { required?: string[]; available?: string[] };
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

type ResolvedRoute = { root: string; nodes: string[]; edges: RouteEdge[] };
type CoverageRow = { id: string; status: CoverageStatus; controls: string[]; detections: string[]; evidence: string[]; gaps: string[]; owners: string[] };
type AttackLayer = ReturnType<typeof buildAttackNavigatorLayer>;
type D3fendCadGraph = ReturnType<typeof buildD3fendCadGraph>;

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
  const [bundleSource, setBundleSource] = useState<BundleSource>('fallback');
  const [query, setQuery] = useState<string>('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('route');
  const [searchError, setSearchError] = useState<string>('');

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
          setQuery('');
          setSelectedId(null);
        }
      })
      .catch(() => {
        setBundle(fallbackBundle);
        setBundleSource('fallback');
        setQuery('');
        setSelectedId(null);
      });
  }, []);

  const nodeMap = useMemo(() => new Map(bundle.nodes.map((node) => [node.id, node])), [bundle.nodes]);
  const selectedNode = selectedId ? nodeMap.get(selectedId) ?? null : null;
  const activeRoute = useMemo(() => (selectedNode ? resolveRoute(bundle, selectedNode.id) : null), [bundle, selectedNode]);
  const activeNodes = useMemo(() => {
    if (!activeRoute) return [];
    return activeRoute.nodes.map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[];
  }, [activeRoute, nodeMap]);
  const routeNodesByType = useMemo(() => groupNodesByType(activeNodes), [activeNodes]);
  const relatedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return bundle.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id);
  }, [bundle.edges, selectedNode]);
  const suggestions = useMemo(() => buildSuggestions(bundle, query), [bundle, query]);
  const coverageRows = useMemo(() => (activeRoute ? buildCoverageRows(bundle, activeRoute) : []), [bundle, activeRoute]);
  const navigatorLayer = useMemo(() => (activeRoute ? buildAttackNavigatorLayer(bundle, activeRoute) : buildAttackNavigatorLayer(bundle, { root: 'EMPTY', nodes: [], edges: [] })), [bundle, activeRoute]);
  const d3fendCadGraph = useMemo(() => (activeRoute ? buildD3fendCadGraph(bundle, activeRoute) : buildD3fendCadGraph(bundle, { root: 'EMPTY', nodes: [], edges: [] })), [bundle, activeRoute]);
  const markdownExport = useMemo(() => {
    if (!activeRoute || !selectedNode) return '';
    return buildMarkdownExport(bundle, activeRoute, selectedNode);
  }, [bundle, activeRoute, selectedNode]);

  function submitSearch() {
    const term = query.trim();
    const candidate = term.toUpperCase();
    setSearchError('');
    if (!candidate) return;

    const exact = nodeMap.get(candidate);
    if (exact) {
      setSelectedId(exact.id);
      setQuery(exact.id);
      setActiveTab('route');
      return;
    }

    const fuzzy = bundle.nodes.find((node) => `${node.id} ${node.name}`.toLowerCase().includes(term.toLowerCase()));
    if (fuzzy) {
      setSelectedId(fuzzy.id);
      setQuery(fuzzy.id);
      setActiveTab('route');
      return;
    }

    setSelectedId(null);
    setSearchError(`No node found for "${term}" in the loaded bundle.`);
  }

  function clearSearch() {
    setQuery('');
    setSelectedId(null);
    setSearchError('');
    setActiveTab('route');
  }

  function selectNode(id: string) {
    setSelectedId(id);
    setQuery(id);
    setSearchError('');
  }

  return (
    <main className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Attack2Defend Navigator · Search-first</p>
          <h1>Threat-defense route navigator</h1>
          <p className="hero-copy">Search a CVE, CWE, CAPEC, ATT&CK technique, D3FEND technique, artifact, control, detection or evidence node. The UI renders local bundle data only.</p>
          <BundleBanner bundle={bundle} bundleSource={bundleSource} />
          <div className="metric-row">
            <Metric label="Nodes" value={String(bundle.nodes.length)} />
            <Metric label="Edges" value={String(bundle.edges.length)} />
            <Metric label="Routes" value={String(bundle.routes?.length ?? bundle.indexes?.route_inputs?.length ?? 0)} />
            <Metric label="Source" value={bundleSource === 'generated' ? 'Generated bundle' : 'Fallback sample'} />
          </div>
        </div>
        <div className="search-card">
          <label htmlFor="route-search">Search any ID or name</label>
          <div className="search-inline search-inline-with-clear">
            <input id="route-search" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && submitSearch()} placeholder="CVE-2021-44228, T1190, CAPEC-63, CWE-79, D3-MFA..." />
            <button onClick={submitSearch}>Search</button>
            <button className="secondary-button" onClick={clearSearch}>Clear</button>
          </div>
          {searchError && <p className="search-error">{searchError}</p>}
          {query.trim() && suggestions.length > 0 && (
            <div className="suggestions">
              {suggestions.map((node) => (
                <button key={node.id} onClick={() => selectNode(node.id)}>
                  <strong>{node.id}</strong><span>{node.name}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </header>

      <nav className="tabs" aria-label="Navigator tabs">
        {[
          ['route', 'Route Flow'],
          ['attack', 'ATT&CK Navigator'],
          ['d3fend', 'D3FEND CAD'],
          ['coverage', 'Coverage'],
          ['export', 'Export'],
        ].map(([id, label]) => (
          <button key={id} className={activeTab === id ? 'active' : ''} onClick={() => setActiveTab(id as TabId)}>{label}</button>
        ))}
      </nav>

      {!selectedNode || !activeRoute ? (
        <EmptyState bundleSource={bundleSource} />
      ) : (
        <>
          {activeTab === 'route' && (
            <section className="grid route-layout">
              <div className="panel wide">
                <PanelTitle title="Route Flow" subtitle="CVE → CWE → CAPEC → ATT&CK → Artifact → D3FEND → Control → Detection → Evidence → Gap." />
                <RouteColumns nodesByType={routeNodesByType} selectedId={selectedNode.id} onSelect={selectNode} />
                <RelationshipStrip edges={activeRoute.edges} />
              </div>
              <NodeDetail node={selectedNode} relatedEdges={relatedEdges} onSelect={selectNode} nodeMap={nodeMap} />
              <ActionSummary node={selectedNode} activeRoute={activeRoute} coverageRows={coverageRows} />
            </section>
          )}

          {activeTab === 'attack' && <AttackNavigatorTab bundle={bundle} activeRoute={activeRoute} navigatorLayer={navigatorLayer} />}
          {activeTab === 'd3fend' && <D3fendCadTab bundle={bundle} activeRoute={activeRoute} cadGraph={d3fendCadGraph} />}
          {activeTab === 'coverage' && <CoverageTab rows={coverageRows} bundle={bundle} />}
          {activeTab === 'export' && <ExportTab markdown={markdownExport} routeJson={JSON.stringify({ route: activeRoute, selected: selectedNode, coverage: coverageRows }, null, 2)} navigatorLayer={JSON.stringify(navigatorLayer, null, 2)} cadGraph={JSON.stringify(d3fendCadGraph, null, 2)} />}
        </>
      )}
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function PanelTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return <div className="panel-title"><h2>{title}</h2><p>{subtitle}</p></div>;
}

function BundleBanner({ bundle, bundleSource }: { bundle: KnowledgeBundle; bundleSource: BundleSource }) {
  const generatedAt = bundle.metadata.generated_at ?? 'not available';
  const mode = bundle.metadata.mode ?? 'unknown';
  const warnings = bundle.metadata.warnings?.length ?? 0;
  const publicSources = bundle.metadata.public_sources?.length ?? 0;
  const publicFailures = bundle.metadata.public_source_failures?.length ?? 0;

  return (
    <div className={`bundle-banner ${bundleSource}`}>
      <strong>{bundleSource === 'generated' ? 'Generated bundle loaded' : 'Fallback sample loaded'}</strong>
      <span>mode: {mode}</span>
      <span>generated: {generatedAt}</span>
      <span>public sources: {publicSources}</span>
      <span>warnings: {warnings + publicFailures}</span>
      {bundleSource === 'fallback' && <em>No generated bundle was found. Run the builder before treating this as pre-production data.</em>}
    </div>
  );
}

function EmptyState({ bundleSource }: { bundleSource: BundleSource }) {
  return (
    <section className="panel empty-state">
      <h2>Search to begin</h2>
      <p>Enter a CVE, CWE, CAPEC, ATT&CK technique, D3FEND technique, artifact, control, detection or evidence node. Nothing is pre-selected.</p>
      <div className="empty-examples">
        <code>CVE-2021-44228</code>
        <code>T1190</code>
        <code>CAPEC-63</code>
        <code>CWE-79</code>
        <code>D3-MFA</code>
      </div>
      {bundleSource === 'fallback' && <p className="fallback-warning">Fallback sample is available only for development resilience. Generate <code>/data/knowledge-bundle.json</code> for real validation.</p>}
    </section>
  );
}

function RouteColumns({ nodesByType, selectedId, onSelect }: { nodesByType: Map<NodeType, RouteNode[]>; selectedId: string; onSelect: (id: string) => void }) {
  return (
    <div className="columns pro-columns route-flow-columns">
      {typeOrder.map((type) => (
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

function RelationshipStrip({ edges }: { edges: RouteEdge[] }) {
  return (
    <div className="relationship-strip">
      {edges.slice(0, 40).map((edge) => (
        <span key={`${edge.source}-${edge.relationship}-${edge.target}`}>
          <code>{edge.source}</code> {relationshipLabels[edge.relationship] ?? edge.relationship} <code>{edge.target}</code>
          {edge.confidence && <em>{edge.confidence}</em>}
        </span>
      ))}
      {edges.length > 40 && <span>Showing first 40 relationships of {edges.length}.</span>}
    </div>
  );
}

function NodeDetail({ node, relatedEdges, onSelect, nodeMap }: { node: RouteNode; relatedEdges: RouteEdge[]; onSelect: (id: string) => void; nodeMap: Map<string, RouteNode> }) {
  return (
    <aside className="panel">
      <PanelTitle title="Selected Node" subtitle="Direct relationships and source context." />
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

function ActionSummary({ node, activeRoute, coverageRows }: { node: RouteNode; activeRoute: ResolvedRoute; coverageRows: CoverageRow[] }) {
  return (
    <aside className="panel analyst-card">
      <PanelTitle title="Deterministic Actions" subtitle="No AI. Actions are generated from the resolved route." />
      <ul className="action-list">
        {buildCtiActions(node, activeRoute).map((item) => <li key={item}>{item}</li>)}
        {buildHuntingActions(node, activeRoute).map((item) => <li key={item}>{item}</li>)}
        {buildSocActions(activeRoute, coverageRows).map((item) => <li key={item}>{item}</li>)}
      </ul>
    </aside>
  );
}

function AttackNavigatorTab({ bundle, activeRoute, navigatorLayer }: { bundle: KnowledgeBundle; activeRoute: ResolvedRoute; navigatorLayer: AttackLayer }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const attackNodes = activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => node?.type === 'attack');
  return (
    <section className="grid two-col">
      <section className="panel">
        <PanelTitle title="ATT&CK Navigator Layer" subtitle="Simple export compatible with ATT&CK Navigator. This project does not reimplement Navigator." />
        <LinkList nodes={attackNodes} />
        <DownloadLinks filename={`attack2defend-${activeRoute.root}-attack-layer.json`} payload={navigatorLayer} />
      </section>
      <section className="panel">
        <PanelTitle title="Layer JSON Preview" subtitle="Open or import this JSON in ATT&CK Navigator." />
        <textarea value={JSON.stringify(navigatorLayer, null, 2)} readOnly />
      </section>
    </section>
  );
}

function D3fendCadTab({ bundle, activeRoute, cadGraph }: { bundle: KnowledgeBundle; activeRoute: ResolvedRoute; cadGraph: D3fendCadGraph }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const d3fendNodes = activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => node?.type === 'd3fend');
  return (
    <section className="grid two-col">
      <section className="panel">
        <PanelTitle title="D3FEND CAD Graph" subtitle="CAD-style graph export for Attack / Countermeasure / Artifact route context." />
        <LinkList nodes={d3fendNodes} />
        <DownloadLinks filename={`attack2defend-${activeRoute.root}-d3fend-cad.json`} payload={cadGraph} />
      </section>
      <section className="panel">
        <PanelTitle title="CAD JSON Preview" subtitle="Prepared for future D3FEND CAD import/embed workflow." />
        <textarea value={JSON.stringify(cadGraph, null, 2)} readOnly />
      </section>
    </section>
  );
}

function DownloadLinks({ filename, payload }: { filename: string; payload: unknown }) {
  const href = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(payload, null, 2))}`;
  return <div className="download-row"><a href={href} download={filename}>Download JSON</a></div>;
}

function LinkList({ nodes }: { nodes: RouteNode[] }) {
  return <ul className="link-list">{nodes.length === 0 && <li>No matching nodes in active route.</li>}{nodes.map((node) => <li key={node.id}>{node.url ? <a href={node.url} target="_blank" rel="noreferrer">{node.id} · {node.name}</a> : `${node.id} · ${node.name}`}</li>)}</ul>;
}

function CoverageTab({ rows, bundle }: { rows: CoverageRow[]; bundle: KnowledgeBundle }) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  return (
    <section className="panel">
      <PanelTitle title="Coverage" subtitle="Curated/internal coverage merged with the active route." />
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

function ExportTab({ markdown, routeJson, navigatorLayer, cadGraph }: { markdown: string; routeJson: string; navigatorLayer: string; cadGraph: string }) {
  return (
    <section className="grid two-col">
      <section className="panel"><PanelTitle title="Markdown Export" subtitle="Ready for CTI/TH/SOC notes." /><textarea value={markdown} readOnly /></section>
      <section className="panel"><PanelTitle title="Route JSON Export" subtitle="Active route and coverage." /><textarea value={routeJson} readOnly /></section>
      <section className="panel"><PanelTitle title="ATT&CK Layer Export" subtitle="Navigator-compatible starter layer." /><textarea value={navigatorLayer} readOnly /></section>
      <section className="panel"><PanelTitle title="D3FEND CAD Graph Export" subtitle="CAD-style graph payload." /><textarea value={cadGraph} readOnly /></section>
    </section>
  );
}

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
  if (!term) return [];
  return bundle.nodes.filter((node) => `${node.id} ${node.name}`.toLowerCase().includes(term)).slice(0, 8);
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

function buildAttackNavigatorLayer(bundle: KnowledgeBundle, route: ResolvedRoute) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  return {
    name: `Attack2Defend layer - ${route.root}`,
    versions: { attack: 'unknown', navigator: '5.x-compatible', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Generated starter layer from Attack2Defend active route.',
    techniques: route.nodes
      .map((id) => nodeMap.get(id))
      .filter((node): node is RouteNode => Boolean(node && node.type === 'attack'))
      .map((node) => ({ techniqueID: node.id, score: 1, comment: node.name })),
  };
}

function buildD3fendCadGraph(bundle: KnowledgeBundle, route: ResolvedRoute) {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const nodes = route.nodes
    .map((id) => nodeMap.get(id))
    .filter((node): node is RouteNode => Boolean(node && ['attack', 'artifact', 'd3fend'].includes(node.type)))
    .map((node) => ({
      id: node.id,
      label: node.name,
      type: node.type,
      d3f_class: node.type === 'attack' ? 'Attack' : node.type === 'd3fend' ? 'Countermeasure' : 'DigitalArtifact',
      url: node.url ?? null,
    }));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = route.edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge) => ({
      source: edge.source,
      target: edge.target,
      relationship: edge.relationship,
      d3f_property: edge.relationship,
      confidence: edge.confidence ?? 'unknown',
    }));
  return {
    name: `Attack2Defend D3FEND CAD graph - ${route.root}`,
    format: 'attack2defend-d3fend-cad-like.v1',
    root: route.root,
    nodes,
    edges,
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

createRoot(document.getElementById('root')!).render(<App />);

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import fallbackRoute from './data/log4shell.route.json';
import './styles.css';
import { RouteGraphTab } from './RouteGraph';
import { buildRouteViewModel, buildRouteViewModelFromPreview } from './lib/routeViewModel';
import { startRouteResolution, getOrchestratorModePublic } from './lib/routeOrchestratorClient';
import type { ResolutionStatus, ResolutionStep, RouteResolutionJobStatus } from './lib/routeOrchestratorClient';
import type { PreviewRouteArtifact, RouteViewModel } from './lib/routeViewModel';
import { A2DAppShell } from './components/A2DAppShell';

type NodeType = 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend' | 'artifact' | 'control' | 'detection' | 'evidence' | 'gap' | 'action';
type CoverageStatus = 'covered' | 'partial' | 'missing' | 'unknown' | 'not_applicable';
type TabId = 'route' | 'attack' | 'd3fend' | 'coverage' | 'export' | 'graph';
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
  source_kind?: string;
  owner?: string;
  priority?: string;
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
    search?: Array<{ id: string; type: string; name: string; text: string }>;
    cpe_to_cve?: Record<string, string[]>;
    kev?: Record<string, Record<string, unknown>>;
    forward?: Record<string, Record<string, string[]>>;
    reverse?: Record<string, Record<string, string[]>>;
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
type CapabilityNode = RouteNode & { sourceRef: string; officialLink: string };
type CapabilitySection = { type: NodeType; label: string; nodes: CapabilityNode[]; emptyMessage: string };
type CapabilityBridge = { source: string; target: string; relationship: string; confidence: string; source_ref: string };
type CuratedRoute = { stages: Array<{ type: NodeType; label: string; nodes: CapabilityNode[] }>; counts: Partial<Record<NodeType, number>>; isPending: boolean };
type AiCuratedRouteArtifact = {
  ai_status: string;
  selection_method: string;
  input?: string;
  normalized_input?: string;
  input_type?: NodeType | string;
  narrative_status?: string;
  llm_adapter: { used: boolean; reason?: string };
  provider: string;
  model: string;
  validator_status: string;
  generated_at: string;
  narrative?: {
    schema_version?: string;
    generated_at?: string;
    status?: string;
    summary_es?: string;
    executive_summary_es?: string;
    decision_context_es?: string;
    risk_rationale_es?: string;
    consultative_conclusion_es?: string[];
    recommended_validations?: Array<{ owner: string; text: string; evidence_expected?: string[]; source_ids?: string[] }>;
    suggested_detections?: Array<{ text: string; source_ids?: string[] } | string>;
    stage_summaries?: Array<{ type: NodeType | string; text: string }>;
    node_reasons?: Array<{ id: string; reason_es: string }>;
    node_reason_by_id?: Record<string, string>;
  };
  curated_route: Record<string, unknown>;
};

type RecommendedAction = { id: string; type: 'action'; description_es: string; owner_guidance_es: string; source_ref: string; related_gap_id: string };
type CapabilityView = {
  capability: 'attack2defend.resolve_defense_route';
  input: string;
  normalized_input: string;
  input_type: NodeType | 'unknown';
  coverage_status: string;
  confidence: string;
  executive_summary_es: string;
  decision_context_es: string;
  risk_rationale_es: string;
  consultative_conclusion_es: string[];
  threatStatus: string;
  defenseStatus: string;
  priority: {
    threat_relevance: string;
    exposure: string;
    defense_gap: string;
    final_priority: string;
    rationale: string;
    rationale_es: string;
  };
  threatSections: CapabilitySection[];
  defenseSections: CapabilitySection[];
  bridges: CapabilityBridge[];
  recommended_actions: RecommendedAction[];
  recommended_validations: Array<{ owner: string; text: string; evidence_expected?: string[]; source_ids?: string[] }>;
  suggested_detections: string[];
  node_reason_by_id: Record<string, string>;
  owners: string[];
  source_refs: string[];
  official_links: Array<{ node_id: string; node_type: string; url: string; source: string }>;
  gap_explanation_es: string;
  exportPayload: Record<string, unknown>;
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

const typeOrder: NodeType[] = ['cve', 'artifact', 'cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'];
const threatMapTypes: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend'];
const defenseMapTypes: NodeType[] = ['control', 'detection', 'evidence', 'gap', 'action'];

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
  action: 'Action',
};

const relationshipLabels: Record<string, string> = {
  has_weakness: 'has weakness',
  has_related_weakness: 'related weakness',
  vulnerability_has_weakness: 'has weakness',
  may_enable_attack_pattern: 'may enable',
  weakness_enables_attack_pattern: 'may enable',
  may_map_to_attack_technique: 'maps to',
  attack_pattern_maps_to_technique: 'maps to',
  may_lead_to_post_exploitation: 'may lead to',
  affects_artifact: 'affects',
  affects_or_requires_artifact: 'requires artifact',
  affects_product_or_platform: 'affects product',
  abuses_artifact: 'abuses',
  targets_artifact: 'targets',
  protects_artifact: 'protects',
  may_be_defended_by: 'defended by',
  may_be_detected_by: 'detected by',
  implemented_by: 'implemented by',
  protected_by_control: 'implemented by control',
  enables_detection: 'enables',
  validated_by_detection: 'validated by',
  requires_evidence: 'requires',
  missing_evidence_creates_gap: 'creates gap',
  closed_by_action: 'closed by',
  technique_mitigated_by_countermeasure: 'mitigated by',
};

const allowedForwardTypeTransitions: Partial<Record<NodeType, NodeType[]>> = {
  cve: ['artifact', 'cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  artifact: ['cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  cwe: ['cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  capec: ['attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  attack: ['artifact', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  d3fend: ['artifact', 'control', 'detection', 'evidence', 'gap', 'action'],
  control: ['detection', 'evidence', 'gap', 'action'],
  detection: ['evidence', 'gap', 'action'],
  evidence: ['gap', 'action'],
  gap: ['action'],
  action: [],
};

function App() {
  const [bundle, setBundle] = useState<KnowledgeBundle>(fallbackBundle);
  const [bundleSource, setBundleSource] = useState<BundleSource>('fallback');
  const [aiArtifact, setAiArtifact] = useState<AiCuratedRouteArtifact | null>(null);
  const [query, setQuery] = useState<string>('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<TabId>('route');
  const [searchError, setSearchError] = useState<string>('');

  // On-demand resolution state
  const [resolutionStatus, setResolutionStatus] = useState<ResolutionStatus>('idle');
  const [resolutionSteps, setResolutionSteps] = useState<ResolutionStep[]>([]);
  const [resolutionProgress, setResolutionProgress] = useState<number>(0);
  const [resolutionMessage, setResolutionMessage] = useState<string>('');
  const [resolutionWarnings, setResolutionWarnings] = useState<string[]>([]);
  const [resolutionError, setResolutionError] = useState<string>('');
  const [previewArtifact, setPreviewArtifact] = useState<PreviewRouteArtifact | null>(null);

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
          setSelectedIds([]);
        }
      })
      .catch(() => {
        setBundle(fallbackBundle);
        setBundleSource('fallback');
        setQuery('');
        setSelectedIds([]);
      });
  }, []);

  useEffect(() => {
    fetch('/data/ai-curated-route.json')
      .then((response) => {
        if (!response.ok) return null;
        return response.json() as Promise<AiCuratedRouteArtifact>;
      })
      .then((artifact) => {
        setAiArtifact(artifact);
      })
      .catch(() => {
        setAiArtifact(null);
      });
  }, []);

  const nodeMap = useMemo(() => new Map(bundle.nodes.map((node) => [node.id, node])), [bundle.nodes]);
  const selectedNode = selectedIds.length ? nodeMap.get(selectedIds[0]) ?? null : null;
  const activeRoute = useMemo(() => (selectedIds.length ? resolveRoute(bundle, selectedIds) : null), [bundle, selectedIds]);
  const suggestions = useMemo(() => buildSuggestions(bundle, query), [bundle, query]);
  const coverageRows = useMemo(() => (activeRoute ? buildCoverageRows(bundle, activeRoute) : []), [bundle, activeRoute]);
  const navigatorLayer = useMemo(() => (activeRoute ? buildAttackNavigatorLayer(bundle, activeRoute) : buildAttackNavigatorLayer(bundle, { root: 'EMPTY', nodes: [], edges: [] })), [bundle, activeRoute]);
  const d3fendCadGraph = useMemo(() => (activeRoute ? buildD3fendCadGraph(bundle, activeRoute) : buildD3fendCadGraph(bundle, { root: 'EMPTY', nodes: [], edges: [] })), [bundle, activeRoute]);
  const activeAiArtifact = useMemo(() => {
    if (!aiArtifact || !selectedNode) return null;
    const curatedRouteInput = aiArtifact.curated_route && typeof aiArtifact.curated_route === 'object'
      ? String((aiArtifact.curated_route as Record<string, unknown>).input ?? '')
      : '';
    const artifactInput = String(aiArtifact.input || curatedRouteInput).toUpperCase();
    return artifactInput && artifactInput === selectedNode.id.toUpperCase() ? aiArtifact : null;
  }, [aiArtifact, selectedNode]);
  const capabilityView = useMemo(() => (activeRoute && selectedNode ? buildCapabilityView(bundle, activeRoute, selectedNode, activeAiArtifact) : null), [bundle, activeRoute, selectedNode, activeAiArtifact]);
  const curatedRoute = useMemo(() => (capabilityView ? buildCuratedRoute(capabilityView) : null), [capabilityView]);
  const markdownExport = useMemo(() => {
    if (!activeRoute || !selectedNode) return '';
    return buildMarkdownExport(bundle, activeRoute, selectedNode);
  }, [bundle, activeRoute, selectedNode]);
  const capabilityJson = useMemo(() => (capabilityView && curatedRoute ? JSON.stringify(buildCapabilityExportPackage(capabilityView, curatedRoute), null, 2) : ''), [capabilityView, curatedRoute]);

  const routeViewModel = useMemo<RouteViewModel>(() => {
    if (previewArtifact && resolutionStatus !== 'idle' && resolutionStatus !== 'local_found' && !selectedIds.length) {
      return buildRouteViewModelFromPreview(previewArtifact);
    }
    return buildRouteViewModel({ bundle, query, selectedIds, aiTask: 'explain_visible_graph' });
  }, [bundle, query, selectedIds, previewArtifact, resolutionStatus]);

  const isPreview = routeViewModel.isPreview;

  const startResolution = useCallback(async (input: string) => {
    setResolutionStatus('queued');
    setResolutionSteps([]);
    setResolutionProgress(0);
    setResolutionMessage(`${input} not found in local bundle. Starting preview resolution...`);
    setResolutionWarnings([]);
    setResolutionError('');
    setPreviewArtifact(null);

    let result: RouteResolutionJobStatus;
    try {
      result = await startRouteResolution(input, (steps, progress) => {
        setResolutionSteps(steps);
        setResolutionProgress(progress);
        setResolutionStatus('running');
      });
    } catch (err) {
      setResolutionStatus('failed');
      setResolutionError(err instanceof Error ? err.message : 'Unknown resolution error.');
      return;
    }

    setResolutionSteps(result.steps ?? []);
    setResolutionProgress(result.progress ?? 100);
    setResolutionWarnings(result.warnings ?? []);
    setResolutionError(result.error ?? '');

    if (result.status === 'disabled') {
      setResolutionStatus('disabled');
      setResolutionMessage('');
      return;
    }

    if ((result.status === 'completed' || result.status === 'completed_with_gaps') && result.preview_artifact) {
      setPreviewArtifact(result.preview_artifact);
      setResolutionStatus(result.status);
      setResolutionMessage('');
      return;
    }

    setResolutionStatus(result.status === 'failed' ? 'failed' : 'failed');
    setResolutionMessage('');
  }, []);

  function submitSearch() {
    const term = query.trim();
    const candidate = term.toUpperCase();
    setSearchError('');
    setPreviewArtifact(null);
    setResolutionStatus('idle');
    setResolutionSteps([]);
    setResolutionProgress(0);
    setResolutionMessage('');
    setResolutionWarnings([]);
    setResolutionError('');

    if (!candidate) return;

    const exact = nodeMap.get(candidate);
    if (exact) {
      selectNode(exact.id);
      setActiveTab('route');
      setResolutionStatus('local_found');
      return;
    }

    const fuzzy = bundle.nodes.find((node) => `${node.id} ${node.name}`.toLowerCase().includes(term.toLowerCase()));
    if (fuzzy) {
      selectNode(fuzzy.id);
      setActiveTab('route');
      setResolutionStatus('local_found');
      return;
    }

    // Not in local bundle — start on-demand resolution
    setSelectedIds([]);
    setResolutionStatus('local_not_found');
    setResolutionMessage(`"${candidate}" not found in the local bundle.`);

    const orchestratorMode = getOrchestratorModePublic();
    if (orchestratorMode === 'disabled') {
      setResolutionStatus('disabled');
      return;
    }

    void startResolution(candidate);
  }

  function clearSearch() {
    setQuery('');
    setSelectedIds([]);
    setSearchError('');
    setActiveTab('route');
    setResolutionStatus('idle');
    setResolutionSteps([]);
    setResolutionProgress(0);
    setResolutionMessage('');
    setResolutionWarnings([]);
    setResolutionError('');
    setPreviewArtifact(null);
  }

  function selectNode(id: string) {
    setSelectedIds((prev) => prev.includes(id) ? [id, ...prev.filter((item) => item !== id)] : [id, ...prev].slice(0, 5));
    setQuery(id);
    setSearchError('');
  }

  return (
    <main className="app-shell">
      <A2DAppShell
        query={query}
        viewModel={routeViewModel}
        onQueryChange={setQuery}
        onAnalyze={submitSearch}
        searchError={searchError}
        resolutionStatus={resolutionStatus === 'idle' || resolutionStatus === 'local_found' ? undefined : resolutionStatus}
        resolutionSteps={resolutionSteps}
        resolutionProgress={resolutionProgress}
        resolutionMessage={resolutionMessage}
        resolutionWarnings={resolutionWarnings}
        resolutionError={resolutionError}
        isPreview={isPreview}
        onRetryResolution={() => {
          const candidate = query.trim().toUpperCase();
          if (candidate) void startResolution(candidate);
        }}
      />

      <details className="legacy-technical">
        <summary>Legacy / Technical Details</summary>

      <header className="hero">
        <div>
          <p className="eyebrow">Attack2Defend</p>
          <h1>Attack2Defend</h1>
          <p className="hero-copy">Convierte vulnerabilidades en decisiones defensivas accionables.</p>
        </div>
        <div className="search-card">
          <label htmlFor="route-search">Buscar ID o nombre</label>
          <div className="search-inline search-inline-with-clear">
            <input id="route-search" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && submitSearch()} placeholder="CVE-2026-41940, CVE-2021-44228, T1190, CWE-306..." />
            <button onClick={submitSearch}>Buscar</button>
            <button className="secondary-button" onClick={clearSearch}>Limpiar</button>
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
          ['route', 'Análisis'],
          ['graph', 'Ruta Visual'],
          ['attack', 'ATT&CK Navigator'],
          ['d3fend', 'D3FEND CAD'],
          ['coverage', 'Coverage'],
          ['export', 'Exportar JSON'],
        ].map(([id, label]) => (
          <button key={id} className={activeTab === id ? 'active' : ''} onClick={() => setActiveTab(id as TabId)}>{label}</button>
        ))}
      </nav>

      {!selectedIds.length || !activeRoute || !selectedNode ? (
        <EmptyState bundleSource={bundleSource} />
      ) : (
        <>
          {activeTab === 'route' && (
            capabilityView && curatedRoute ? <AnalysisTab view={capabilityView} curatedRoute={curatedRoute} bundle={bundle} bundleSource={bundleSource} onSelect={selectNode} aiArtifact={activeAiArtifact} /> : null
          )}

          {activeTab === 'graph' && <RouteGraphTab bundle={bundle} activeRoute={activeRoute} selectedNode={selectedNode} />}
          {activeTab === 'attack' && <AttackNavigatorTab bundle={bundle} activeRoute={activeRoute} navigatorLayer={navigatorLayer} />}
          {activeTab === 'd3fend' && <D3fendCadTab bundle={bundle} activeRoute={activeRoute} cadGraph={d3fendCadGraph} />}
          {activeTab === 'coverage' && <CoverageTab rows={coverageRows} bundle={bundle} />}
          {activeTab === 'export' && <ExportTab markdown={markdownExport} routeJson={JSON.stringify({ route: activeRoute, selected: selectedNode, coverage: coverageRows }, null, 2)} capabilityJson={capabilityJson} navigatorLayer={JSON.stringify(navigatorLayer, null, 2)} cadGraph={JSON.stringify(d3fendCadGraph, null, 2)} />}
        </>
      )}
      </details>
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
      <h2>Busca para iniciar</h2>
      <p>Ingresa una CVE, CWE, CAPEC, técnica ATT&CK, técnica D3FEND, Control, Detection, Evidence, Gap o Action. Nada se preselecciona: el análisis se deriva del bundle local.</p>
      <div className="empty-examples">
        <code>CVE-2021-44228</code>
        <code>T1190</code>
        <code>CAPEC-63</code>
        <code>CWE-79</code>
        <code>D3-MFA</code>
      </div>
      {bundleSource === 'fallback' && <p className="fallback-warning">El fallback sample solo sirve para resiliencia de desarrollo. Genera <code>/data/knowledge-bundle.json</code> para validación real.</p>}
    </section>
  );
}


function PreliminarySummary({ view }: { view: CapabilityView }) {
  return (
    <section className="panel summary-panel">
      <PanelTitle title="Resumen defensivo preliminar" subtitle="Lectura consultiva derivada solo del bundle local." />
      <div className="summary-grid">
        <SummaryItem label="ID consultado" value={view.normalized_input} />
        <SummaryItem label="Tipo" value={typeLabels[view.input_type as NodeType] ?? 'Desconocido'} />
        <SummaryItem label="Lectura defensiva preliminar" value={preliminaryReading(view)} />
        <SummaryItem label="Prioridad preliminar" value={preliminaryPriority(view.priority.final_priority)} />
        <SummaryItem label="Confianza del mapeo" value={mappingConfidence(view.confidence)} />
      </div>
      <p className="summary-disclaimer">Esta vista no confirma afectación ni cobertura real del entorno. Indica qué debe validarse para considerar el riesgo cubierto.</p>
    </section>
  );
}


function AnalysisTab({ view, curatedRoute, bundle, bundleSource, onSelect, aiArtifact }: { view: CapabilityView; curatedRoute: CuratedRoute; bundle: KnowledgeBundle; bundleSource: BundleSource; onSelect: (id: string) => void; aiArtifact: AiCuratedRouteArtifact | null }) {
  const counts = fullTraceabilityCounts(view);
  const exportPayload = buildCapabilityExportPackage(view, curatedRoute);
  return (
    <section className="analysis-stack">
      {aiArtifact && <AiPanel artifact={aiArtifact} />}
      <PreliminarySummary view={view} />
      <CuratedRoutePanel curatedRoute={curatedRoute} onSelect={onSelect} nodeReasonById={view.node_reason_by_id} />
      <ConclusionPanel view={view} curatedRoute={curatedRoute} />
      <ValidationPanel view={view} />
      <SuggestedDetectionsPanel curatedRoute={curatedRoute} detections={view.suggested_detections} />
      <PotentialGapsPanel />
      <OwnerActionsPanel />
      <FullTraceabilityPanel view={view} counts={counts} onSelect={onSelect} />
      <TechnicalDetailPanel bundle={bundle} bundleSource={bundleSource} view={view} />
      <section className="panel export-primary">
        <PanelTitle title="Exportar JSON" subtitle="Payload portable con capability, ruta curada, conteos de trazabilidad y source_ref sanitizados." />
        <DownloadLinks filename="attack2defend-capability.json" payload={exportPayload} />
        <textarea value={JSON.stringify(exportPayload, null, 2)} readOnly />
      </section>
    </section>
  );
}

function AiPanel({ artifact }: { artifact: AiCuratedRouteArtifact }) {
  const badge = artifact.llm_adapter.used ? "LLM validated" : "Fallback deterministic";
  const badgeClass = artifact.llm_adapter.used ? "ai-badge-llm" : "ai-badge-fallback";
  const fallbackReason = artifact.llm_adapter.reason ? ` (${artifact.llm_adapter.reason})` : "";
  const timestamp = new Date(artifact.generated_at).toLocaleString();
  const narrative = artifact.narrative ?? null;
  const narrativeSummary = narrative?.executive_summary_es || narrative?.summary_es || "Narrativa no disponible; se muestra el artefacto mínimo.";

  return (
    <section className="panel ai-panel">
      <div className="ai-header">
        <h3>Candidato asistido por IA</h3>
        <span className={`ai-badge ${badgeClass}`}>{badge}{fallbackReason}</span>
      </div>
      <div className="ai-details">
        <div className="ai-detail"><strong>Input:</strong> {artifact.input || artifact.normalized_input || 'N/A'}</div>
        <div className="ai-detail"><strong>Provider:</strong> {artifact.provider || 'N/A'}</div>
        <div className="ai-detail"><strong>Model:</strong> {artifact.model || 'N/A'}</div>
        <div className="ai-detail"><strong>Status:</strong> {artifact.validator_status}</div>
        <div className="ai-detail"><strong>Narrative:</strong> {artifact.narrative_status || narrative?.status || 'n/a'}</div>
        <div className="ai-detail"><strong>Generated:</strong> {timestamp}</div>
      </div>
      <p className="ai-summary">{narrativeSummary}</p>
    </section>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return <article className="summary-item"><span>{label}</span><strong>{value}</strong></article>;
}

function CuratedRoutePanel({ curatedRoute, onSelect, nodeReasonById }: { curatedRoute: CuratedRoute; onSelect: (id: string) => void; nodeReasonById: Record<string, string> }) {
  return (
    <section className="panel curated-route-panel">
      <PanelTitle title="Ruta curada de mayor relevancia" subtitle="CVE → CWE → CAPEC → ATT&CK → D3FEND" />
      {curatedRoute.isPending ? <p className="operational-gap">Ruta curada pendiente de validación.</p> : (
        <div className="curated-steps">
          {curatedRoute.stages.map((stage) => (
            <article key={stage.type} className={`curated-stage ${stage.type}`}>
              <header><span>{stage.label}</span><strong>{stage.nodes.length}</strong></header>
              <div className="curated-node-list">
                {stage.nodes.map((node) => <TraceabilityNode key={node.id} node={node} reason={nodeReasonById[node.id.toUpperCase()] ?? ''} onSelect={onSelect} compact />)}
                {!stage.nodes.length && <p>Sin nodo disponible en el bundle.</p>}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function ConclusionPanel({ view, curatedRoute }: { view: CapabilityView; curatedRoute: CuratedRoute }) {
  return (
    <section className="panel consultative-panel">
      <PanelTitle title="Conclusión" subtitle="Síntesis consultiva para priorizar validaciones, no para declarar cobertura." />
      <ul className="consultative-list">
        {view.consultative_conclusion_es.length ? view.consultative_conclusion_es.map((item) => <li key={item}>{item}</li>) : buildConsultativeConclusion(view, curatedRoute).map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function ValidationPanel({ view }: { view: CapabilityView }) {
  return (
    <section className="panel consultative-panel">
      <PanelTitle title="Validaciones recomendadas" subtitle="Owners sugeridos para confirmar afectación, exposición y evidencia operacional." />
      <div className="validation-list">
        {(view.recommended_validations.length ? view.recommended_validations : buildRecommendedValidations(view)).map((item) => (
          <article key={`${item.owner}-${item.text}`} className="validation-card">
            <strong>{item.text}</strong>
            <span>{item.owner}</span>
            {item.evidence_expected?.length ? <small>{item.evidence_expected.join(' · ')}</small> : null}
          </article>
        ))}
      </div>
    </section>
  );
}

function SuggestedDetectionsPanel({ curatedRoute, detections }: { curatedRoute: CuratedRoute; detections: string[] }) {
  const panelDetections = detections.length ? detections : buildSuggestedDetections(curatedRoute);
  return (
    <section className="panel consultative-panel">
      <PanelTitle title="Detecciones sugeridas" subtitle="Ideas de detección a validar o convertir en hunting; no representan detecciones existentes." />
      <ul className="consultative-list">{panelDetections.map((item) => <li key={item}>{item}</li>)}</ul>
    </section>
  );
}

function PotentialGapsPanel() {
  return (
    <section className="panel consultative-panel">
      <PanelTitle title="Brechas potenciales" subtitle="Puntos mínimos que impiden declarar el riesgo como cubierto sin evidencia." />
      <div className="chip-list">{['Inventario no confirmado', 'Exposición no validada', 'Evidencia/logs no confirmados', 'Detección no validada', 'Acción de cierre no documentada'].map((gap) => <span key={gap}>{gap}</span>)}</div>
    </section>
  );
}

function OwnerActionsPanel() {
  const ownerActions: Array<{ owner: string; actions: string[] }> = [
    { owner: 'Vulnerability Manager', actions: ['Confirmar activos afectados y versión o condición vulnerable.', 'Priorizar remediación según exposición y criticidad del activo.'] },
    { owner: 'Infra', actions: ['Validar exposición del servicio o superficie administrativa.', 'Definir reducción temporal de exposición si aplica.'] },
    { owner: 'SOC', actions: ['Revisar logs y evidencia asociada al vector sugerido.', 'Validar hunting de actividad posterior si hay señales.'] },
    { owner: 'Detection Engineering', actions: ['Validar detecciones o queries para la ruta priorizada.', 'Definir evidencia requerida para medir efectividad.'] },
    { owner: 'CTI/TH', actions: ['Revisar contexto de explotación y técnicas plausibles.', 'Priorizar hipótesis de hunting con evidencia observable.'] },
    { owner: 'CSMA', actions: ['Confirmar postura de controles relacionada con la ruta.', 'Definir criterio de cierre con owner y evidencia.'] },
  ];
  return (
    <section className="panel consultative-panel">
      <PanelTitle title="Acciones sugeridas por owner" subtitle="Máximo dos acciones consultivas por rol." />
      <div className="owner-action-grid">{ownerActions.map((group) => <article key={group.owner} className="owner-card"><h3>{group.owner}</h3><ul>{group.actions.map((action) => <li key={action}>{action}</li>)}</ul></article>)}</div>
    </section>
  );
}

function FullTraceabilityPanel({ view, counts, onSelect }: { view: CapabilityView; counts: Partial<Record<NodeType, number>>; onSelect: (id: string) => void }) {
  return (
    <details className="panel details-panel">
      <summary><span>Trazabilidad completa</span><strong>{formatTraceabilityCounts(counts)}</strong><em>Ver detalle técnico</em></summary>
      <div className="traceability-groups">
        {view.threatSections.map((section) => <TraceabilityGroup key={section.type} section={section} onSelect={onSelect} nodeReasonById={view.node_reason_by_id} />)}
      </div>
    </details>
  );
}

function TraceabilityGroup({ section, onSelect, nodeReasonById }: { section: CapabilitySection; onSelect: (id: string) => void; nodeReasonById: Record<string, string> }) {
  return (
    <article className={`traceability-group ${section.type}`}>
      <header><h3>{section.label}</h3><span>{section.nodes.length}</span></header>
      <div className="traceability-node-grid">
        {section.nodes.map((node) => <TraceabilityNode key={node.id} node={node} reason={nodeReasonById[node.id.toUpperCase()] ?? ''} onSelect={onSelect} />)}
        {!section.nodes.length && <p className="operational-gap">{section.emptyMessage}</p>}
      </div>
    </article>
  );
}

function TraceabilityNode({ node, onSelect, compact = false, reason = '' }: { node: CapabilityNode; onSelect: (id: string) => void; compact?: boolean; reason?: string }) {
  return (
    <article className={`traceability-node ${node.type} ${compact ? 'compact' : ''}`}>
      <button onClick={() => onSelect(node.id)}>{node.id}</button>
      <strong>{node.name}</strong>
      {node.officialLink && <a href={node.officialLink} target="_blank" rel="noreferrer">Official link</a>}
      {reason ? <p className="traceability-reason">{reason}</p> : null}
      <small>source_ref: {node.sourceRef && node.sourceRef !== 'missing_source_ref' ? node.sourceRef : 'missing_source_ref'}</small>
    </article>
  );
}

function TechnicalDetailPanel({ bundle, bundleSource, view }: { bundle: KnowledgeBundle; bundleSource: BundleSource; view: CapabilityView }) {
  const generatedAt = bundle.metadata.generated_at ?? 'not available';
  const mode = bundle.metadata.mode ?? 'unknown';
  const warnings = (bundle.metadata.warnings?.length ?? 0) + (bundle.metadata.public_source_failures?.length ?? 0);
  return (
    <details className="panel details-panel technical-details">
      <summary><span>Detalle técnico</span><strong>{bundle.nodes.length} nodes · {bundle.edges.length} edges · {bundle.routes?.length ?? bundle.indexes?.route_inputs?.length ?? 0} routes</strong><em>Expandir</em></summary>
      <div className="technical-grid">
        <SummaryItem label="Fuente del bundle" value={bundleSource === 'generated' ? 'Generated bundle' : 'Fallback sample'} />
        <SummaryItem label="Modo" value={mode} />
        <SummaryItem label="Generado" value={generatedAt} />
        <SummaryItem label="Warnings" value={String(warnings)} />
        <SummaryItem label="Official links" value={String(view.official_links.length)} />
        <SummaryItem label="Source refs portables" value={String(view.source_refs.length)} />
      </div>
    </details>
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

function NodeDetail({ node, relatedEdges, onSelect, nodeMap, bundle }: { node: RouteNode; relatedEdges: RouteEdge[]; onSelect: (id: string) => void; nodeMap: Map<string, RouteNode>; bundle: KnowledgeBundle }) {
  return (
    <aside className="panel">
      <PanelTitle title="Selected Node" subtitle="Direct relationships and source context." />
      <div className={`detail-badge ${node.type}`}>{typeLabels[node.type]}</div>
      <h3>{node.id}</h3>
      <p className="node-name">{node.name}</p>
      {node.url && <a href={node.url} target="_blank" rel="noreferrer">Open official reference</a>}
      {node.type === 'cve' && <KevPanel node={node} bundle={bundle} />}
      {isCpeNode(node) && <CpePanel node={node} bundle={bundle} onSelect={onSelect} />}
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
                <small>{edge.source_kind ?? 'unknown source'} · {edge.confidence ?? 'unknown confidence'} · {edge.owner ?? 'unowned'} · {edge.priority ?? 'normal'}</small>
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

function ExportTab({ markdown, routeJson, capabilityJson, navigatorLayer, cadGraph }: { markdown: string; routeJson: string; capabilityJson: string; navigatorLayer: string; cadGraph: string }) {
  const capabilityPayload = capabilityJson ? JSON.parse(capabilityJson) : {};
  return (
    <section className="grid two-col">
      <section className="panel export-primary">
        <PanelTitle title="Exportar JSON" subtitle="Capability JSON portable para revisión, automatización y evidencia de decisión." />
        <DownloadLinks filename="attack2defend-capability.json" payload={capabilityPayload} />
        <textarea value={capabilityJson} readOnly />
      </section>
      <section className="panel"><PanelTitle title="Markdown Export" subtitle="Ready for CTI/TH/SOC notes." /><textarea value={markdown} readOnly /></section>
      <section className="panel"><PanelTitle title="Route JSON Export" subtitle="Active route and coverage." /><textarea value={routeJson} readOnly /></section>
      <section className="panel"><PanelTitle title="ATT&CK Layer Export" subtitle="Navigator-compatible starter layer." /><textarea value={navigatorLayer} readOnly /></section>
      <section className="panel"><PanelTitle title="D3FEND CAD Graph Export" subtitle="CAD-style graph payload." /><textarea value={cadGraph} readOnly /></section>
    </section>
  );
}

function resolveRoute(bundle: KnowledgeBundle, roots: string[]): ResolvedRoute {
  const starts = roots.map((item) => item.toUpperCase()).filter(Boolean);
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const outgoing = new Map<string, RouteEdge[]>();
  for (const edge of bundle.edges) {
    const current = outgoing.get(edge.source) ?? [];
    current.push(edge);
    outgoing.set(edge.source, current);
  }

  const queue: Array<{ id: string; depth: number }> = starts
    .filter((id) => nodeMap.has(id))
    .map((id) => ({ id, depth: 0 }));
  const visited = new Set<string>(queue.map((item) => item.id));
  const routeEdges: RouteEdge[] = [];

  while (queue.length) {
    const current = queue.shift();
    if (!current || current.depth >= 5) continue;

    const currentNode = nodeMap.get(current.id);
    if (!currentNode) continue;

    const edges = outgoing.get(current.id) ?? [];
    for (const edge of edges) {
      const nextNode = nodeMap.get(edge.target);
      if (!nextNode) continue;
      if (!isAllowedForwardTransition(currentNode.type, nextNode.type)) continue;

      routeEdges.push(edge);
      if (visited.has(nextNode.id)) continue;
      visited.add(nextNode.id);
      queue.push({ id: nextNode.id, depth: current.depth + 1 });
    }
  }

  return { root: starts[0], nodes: Array.from(visited), edges: dedupeEdges(routeEdges) };
}

function isAllowedForwardTransition(sourceType: NodeType, targetType: NodeType) {
  return (allowedForwardTypeTransitions[sourceType] ?? []).includes(targetType);
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


function buildCuratedRoute(view: CapabilityView): CuratedRoute {
  const limits: Partial<Record<NodeType, number>> = { cve: 1, cwe: 3, capec: 6, attack: 8, d3fend: 6 };
  const stages = threatMapTypes.map((type) => {
    const section = view.threatSections.find((item) => item.type === type);
    const nodes = [...(section?.nodes ?? [])]
      .map((node, index) => ({ node, score: curatedNodeScore(node, type, index) }))
      .sort((left, right) => right.score - left.score || left.node.id.localeCompare(right.node.id))
      .slice(0, limits[type] ?? 0)
      .map((item) => item.node);
    return { type, label: typeLabels[type], nodes };
  });
  const counts = Object.fromEntries(stages.map((stage) => [stage.type, stage.nodes.length])) as Partial<Record<NodeType, number>>;
  return { stages, counts, isPending: stages.every((stage) => stage.nodes.length === 0) };
}

function curatedNodeScore(node: CapabilityNode, type: NodeType, index: number) {
  let score = 1000 - index * 10;
  if (node.officialLink) score += 120;
  if (node.sourceRef && node.sourceRef !== 'missing_source_ref') score += 80;
  if (type === 'cwe' && node.id === 'CWE-306') score += 500;
  if (isGenericNode(node)) score -= 70;
  return score;
}

function isGenericNode(node: CapabilityNode) {
  const text = `${node.id} ${node.name} ${node.description ?? ''}`.toLowerCase();
  return ['other', 'generic', 'general', 'unspecified', 'catalog', 'miscellaneous'].some((word) => text.includes(word));
}

function fullTraceabilityCounts(view: CapabilityView): Partial<Record<NodeType, number>> {
  return Object.fromEntries(view.threatSections.map((section) => [section.type, section.nodes.length])) as Partial<Record<NodeType, number>>;
}

function formatTraceabilityCounts(counts: Partial<Record<NodeType, number>>) {
  return `CVE ${counts.cve ?? 0} · CWE ${counts.cwe ?? 0} · CAPEC ${counts.capec ?? 0} · ATT&CK ${counts.attack ?? 0} · D3FEND ${counts.d3fend ?? 0}`;
}

function buildCapabilityExportPackage(view: CapabilityView, curatedRoute: CuratedRoute) {
  return sanitizeAny({
    capability_payload: view.exportPayload,
    curated_route: {
      stages: curatedRoute.stages.map((stage) => ({
        type: stage.type,
        label: stage.label,
        nodes: stage.nodes.map(toCapabilityNodeExport),
      })),
      pending_validation: curatedRoute.isPending,
    },
    full_traceability_counts: fullTraceabilityCounts(view),
    sanitized_source_refs: view.source_refs.map(sanitizeSourceRef),
  });
}

function preliminaryReading(view: CapabilityView) {
  const present = view.threatSections.filter((section) => section.nodes.length).map((section) => section.label);
  if (!present.length) return 'Requiere validación: no hay ruta de amenaza suficiente en el bundle local.';
  return `Requiere validación: ruta preliminar con ${present.join(', ')}. Capacidad sugerida y evidencia requerida deben confirmarse en el entorno.`;
}

function preliminaryPriority(priority: string) {
  if (priority === 'high') return 'Prioridad preliminar alta';
  if (priority === 'medium') return 'Prioridad preliminar media';
  if (priority === 'low') return 'Prioridad preliminar baja, sujeta a evidencia requerida';
  return 'Prioridad preliminar por definir';
}

function mappingConfidence(confidence: string) {
  if (confidence === 'high') return 'Confianza del mapeo alta';
  if (confidence === 'medium') return 'Confianza del mapeo media';
  return 'Confianza del mapeo baja o pendiente';
}

function buildConsultativeConclusion(view: CapabilityView, curatedRoute: CuratedRoute) {
  const routeText = curatedRoute.stages.filter((stage) => stage.nodes.length).map((stage) => stage.label.toLowerCase()).join(', ');
  const hasAuth = curatedRoute.stages.some((stage) => stage.nodes.some((node) => `${node.id} ${node.name}`.toLowerCase().includes('auth')));
  const focus = hasAuth ? 'autenticación, acceso, explotación de superficie expuesta y defensas verificables' : `${routeText || 'la ruta disponible'}, exposición, evidencia operacional y defensas verificables`;
  return [
    `La lectura se centra en ${focus}.`,
    'Las rutas posteriores son plausibles, no confirmadas.',
    'La prioridad depende de exposición, versión y evidencia operacional.',
    view.source_refs.length ? 'La trazabilidad completa queda disponible como evidencia de origen, sin declarar cobertura real.' : 'Falta evidencia de origen suficiente para cerrar una decisión sin curaduría adicional.',
  ];
}

function buildRecommendedValidations(view: CapabilityView): Array<{ text: string; owner: string; evidence_expected?: string[] }> {
  const items: Array<{ text: string; owner: string; evidence_expected?: string[] }> = [
    { text: 'Confirmar activos afectados', owner: 'Vulnerability Manager / Infra', evidence_expected: ['Inventario/CMDB', 'alcance del activo'] },
    { text: 'Confirmar versión o condición vulnerable', owner: 'Vulnerability Manager', evidence_expected: ['versión instalada', 'advisory o parche'] },
    { text: 'Validar exposición', owner: 'Infra', evidence_expected: ['diagrama de exposición', 'reglas de red o WAF'] },
    { text: 'Revisar logs/evidencia asociada', owner: 'SOC', evidence_expected: ['query o export de logs', 'ventana temporal definida'] },
    { text: 'Validar detecciones o hunting', owner: 'Detection Engineering / SOC', evidence_expected: ['regla o query', 'test case ejecutado'] },
    { text: 'Revisar persistencia si hay señales', owner: 'SOC / DFIR', evidence_expected: ['eventos de persistencia', 'línea temporal de actividad'] },
  ];
  if (view.normalized_input === 'CVE-2026-41940') {
    return [{ text: 'Validar producto afectado, versión, exposición administrativa, logs y evidencia de explotación', owner: 'Vulnerability Manager / Infra / SOC', evidence_expected: ['inventario del producto', 'evidencia de explotación'] }, ...items];
  }
  return items;
}

function buildSuggestedDetections(curatedRoute: CuratedRoute) {
  if (curatedRoute.isPending) return ['Detecciones sugeridas pendientes de curaduría.'];
  const allText = curatedRoute.stages.flatMap((stage) => stage.nodes).map((node) => `${node.id} ${node.name} ${node.description ?? ''}`.toLowerCase()).join(' ');
  const detections = new Set<string>(['Acceso anómalo al servicio expuesto', 'Artefactos de sesión o autenticación sospechosa', 'Cambios administrativos posteriores']);
  if (allText.includes('command') || allText.includes('execution') || allText.includes('execute')) detections.add('Ejecución de comandos post-explotación');
  if (allText.includes('web') || allText.includes('file') || allText.includes('upload')) detections.add('Web shell o modificación de archivos si la ruta lo sugiere');
  return [...detections];
}

function buildCapabilityView(bundle: KnowledgeBundle, route: ResolvedRoute, selectedNode: RouteNode, aiArtifact: AiCuratedRouteArtifact | null = null): CapabilityView {
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const routeNodeIds = new Set(route.nodes);
  const threatIds = new Set(route.nodes.filter((id) => threatMapTypes.includes(nodeMap.get(id)?.type as NodeType)));
  if (threatMapTypes.includes(selectedNode.type)) threatIds.add(selectedNode.id);

  const defenseIds = new Set(route.nodes.filter((id) => defenseMapTypes.includes(nodeMap.get(id)?.type as NodeType)));
  const owners = new Set<string>();
  for (const threatId of threatIds) {
    const record = bundle.coverage?.[threatId];
    if (!record) continue;
    record.owners?.forEach((owner) => owners.add(owner));
    for (const id of [...(record.controls ?? []), ...(record.detections ?? []), ...(record.evidence ?? []), ...(record.gaps ?? [])]) {
      if (nodeMap.get(id)?.type && defenseMapTypes.includes(nodeMap.get(id)!.type)) defenseIds.add(id);
    }
  }
  expandDefenseClosure(bundle, nodeMap, defenseIds);

  const threatNodes = [...threatIds].map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[];
  const defenseNodes = [...defenseIds].map((id) => nodeMap.get(id)).filter(Boolean) as RouteNode[];
  const threatSections = threatMapTypes.map((type) => ({
    type,
    label: typeLabels[type],
    nodes: threatNodes.filter((node) => node.type === type).map(toCapabilityNode),
    emptyMessage: `No hay ${typeLabels[type]} vinculado en la ruta de amenaza local.`,
  }));
  const defenseSections = defenseMapTypes.map((type) => ({
    type,
    label: typeLabels[type],
    nodes: defenseNodes.filter((node) => node.type === type).map(toCapabilityNode),
    emptyMessage: defenseEmptyMessage(type, threatNodes.length > 0),
  }));

  const bridges = buildCapabilityBridges(bundle, nodeMap, route, threatIds, defenseIds);
  const threatStatus = resolveThreatStatus(selectedNode.type, threatSections, bridges);
  const defenseStatus = resolveDefenseStatus(defenseSections, threatNodes);
  const priority = resolveCapabilityPriority(threatNodes, defenseSections);
  const confidence = resolveCapabilityConfidence(route.edges, threatStatus, defenseStatus);
  const officialLinks = threatNodes.map(toCapabilityNode).filter((node) => node.officialLink).map((node) => ({ node_id: node.id, node_type: node.type, url: node.officialLink, source: 'official_framework' }));
  const sourceRefs = collectCapabilitySourceRefs([...threatNodes, ...defenseNodes], route.edges, bridges);
  const curatedRouteView: CuratedRoute = {
    stages: threatMapTypes.map((type) => ({
      type,
      label: typeLabels[type],
      nodes: threatSections.find((section) => section.type === type)?.nodes ?? [],
    })),
    counts: Object.fromEntries(threatMapTypes.map((type) => [type, threatSections.find((section) => section.type === type)?.nodes.length ?? 0])) as Partial<Record<NodeType, number>>,
    isPending: threatNodes.length === 0,
  };
  const narrative = aiArtifact?.narrative ?? null;
  const aiSummary = String(narrative?.executive_summary_es || narrative?.summary_es || buildExecutiveSummaryEs(threatStatus, defenseStatus, priority.final_priority));
  const aiDecisionContext = String(narrative?.decision_context_es || buildDecisionContextEs(threatSections, defenseSections));
  const aiRiskRationale = String(narrative?.risk_rationale_es || buildRiskRationaleEs(priority, defenseSections));
  const aiConclusion = (narrative?.consultative_conclusion_es?.length ? narrative.consultative_conclusion_es : buildConsultativeConclusion({ source_refs: sourceRefs, normalized_input: selectedNode.id, priority } as CapabilityView, curatedRouteView)).map((item) => String(item));
  const aiValidations = narrative?.recommended_validations?.length
    ? narrative.recommended_validations.map((item) => ({
        owner: String(item.owner || 'SOC'),
        text: String(item.text || ''),
        evidence_expected: Array.isArray(item.evidence_expected) ? item.evidence_expected.map((value) => String(value)) : [],
      }))
    : buildRecommendedValidations({ source_refs: sourceRefs, normalized_input: selectedNode.id, priority } as CapabilityView);
  const aiDetections = narrative?.suggested_detections?.length
    ? narrative.suggested_detections.map((item) => (typeof item === 'string' ? item : String(item.text || ''))).filter((item) => item.length > 0)
    : buildSuggestedDetections(curatedRouteView);
  const nodeReasonById = narrative?.node_reason_by_id ?? Object.fromEntries((narrative?.node_reasons ?? []).map((item) => [String(item.id || '').toUpperCase(), String(item.reason_es || '')]).filter(([id, reason]) => id && reason));
  const recommendations = buildRecommendedActionsEs(defenseSections, priority);
  const gapExplanation = buildGapExplanationEs(defenseSections);
  const coverageStatus = defenseStatus !== 'unresolved' ? defenseStatus : threatStatus;

  const exportPayload = {
    capability: 'attack2defend.resolve_defense_route',
    input: selectedNode.id,
    normalized_input: selectedNode.id,
    input_type: selectedNode.type,
    coverage_status: coverageStatus,
    confidence,
    executive_summary_es: aiSummary,
    decision_context_es: aiDecisionContext,
    risk_rationale_es: aiRiskRationale,
    threat_route_map: {
      status: threatStatus,
      nodes: threatSections.flatMap((section) => section.nodes).map(toCapabilityNodeExport),
      edges: route.edges.filter((edge) => isThreatEdge(edge, nodeMap)).map(toCapabilityEdgeExport),
      missing_segments: missingThreatSegments(selectedNode.type, threatSections),
      official_links: officialLinks,
      source_refs: sourceRefs,
    },
    defense_readiness_map: {
      status: defenseStatus,
      summary_es: `Preparación defensiva en estado '${defenseStatus}' con ${defenseNodes.length} nodos operativos.`,
      controls: defenseSections.find((section) => section.type === 'control')!.nodes.map(toCapabilityNodeExport),
      detections: defenseSections.find((section) => section.type === 'detection')!.nodes.map(toCapabilityNodeExport),
      evidence: defenseSections.find((section) => section.type === 'evidence')!.nodes.map(toCapabilityNodeExport),
      gaps: defenseSections.find((section) => section.type === 'gap')!.nodes.map(toCapabilityNodeExport),
      actions: defenseSections.find((section) => section.type === 'action')!.nodes.map(toCapabilityNodeExport),
      gap_explanation_es: gapExplanation,
      missing_segments: missingDefenseSegments(defenseSections),
      source_refs: sourceRefs,
    },
    bridges,
    priority: { ...priority, rationale_es: aiRiskRationale },
    recommended_actions: recommendations,
    consultative_conclusion_es: aiConclusion,
    recommended_validations: aiValidations,
    suggested_detections: aiDetections,
    node_reason_by_id: nodeReasonById,
    owners: [...owners].sort(),
    official_links: officialLinks,
    source_refs: sourceRefs,
    integration_context: {
      gti_ready: true,
      mcp_security_ready: true,
      mcp_server_ready: false,
      requires_runtime_enrichment: false,
    },
    bundle_metadata: {
      contract_version: bundle.metadata.contract_version,
      builder_version: bundle.metadata.builder_version,
      generated_at: bundle.metadata.generated_at,
      mode: bundle.metadata.mode,
      counts: bundle.metadata.counts,
    },
    generated_from: '/data/knowledge-bundle.json',
  };

  return {
    capability: 'attack2defend.resolve_defense_route',
    input: selectedNode.id,
    normalized_input: selectedNode.id,
    input_type: selectedNode.type,
    coverage_status: coverageStatus,
    confidence,
    executive_summary_es: String(exportPayload.executive_summary_es),
    decision_context_es: String(exportPayload.decision_context_es),
    risk_rationale_es: String(exportPayload.risk_rationale_es),
    threatStatus,
    defenseStatus,
    priority: { ...priority, rationale_es: aiRiskRationale },
    threatSections,
    defenseSections,
    bridges,
    recommended_actions: recommendations,
    recommended_validations: aiValidations,
    suggested_detections: aiDetections,
    consultative_conclusion_es: aiConclusion,
    node_reason_by_id: nodeReasonById,
    owners: [...owners].sort(),
    source_refs: sourceRefs,
    official_links: officialLinks,
    gap_explanation_es: gapExplanation,
    exportPayload,
  };
}

function expandDefenseClosure(bundle: KnowledgeBundle, nodeMap: Map<string, RouteNode>, defenseIds: Set<string>) {
  const queue = [...defenseIds];
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of bundle.edges.filter((item) => item.source === current)) {
      const target = nodeMap.get(edge.target);
      if (!target || !defenseMapTypes.includes(target.type)) continue;
      if (!isDefenseRelationship(edge.relationship)) continue;
      if (!defenseIds.has(target.id)) {
        defenseIds.add(target.id);
        queue.push(target.id);
      }
    }
  }
}

function toCapabilityNode(node: RouteNode): CapabilityNode {
  return {
    ...node,
    metadata: sanitizeMetadata(node.metadata),
    sourceRef: nodeSourceRef(node),
    officialLink: officialLinkForNode(node),
  };
}

function toCapabilityNodeExport(node: CapabilityNode) {
  return {
    id: node.id,
    type: node.type,
    name: node.name,
    description: node.description ?? '',
    url: node.url ?? '',
    official_link: node.officialLink,
    source_ref: node.sourceRef,
    metadata: sanitizeMetadata(node.metadata),
  };
}

function toCapabilityEdgeExport(edge: RouteEdge) {
  return {
    source: edge.source,
    target: edge.target,
    relationship: edge.relationship,
    confidence: edge.confidence ?? 'unknown',
    source_ref: sanitizeSourceRef(edge.source_ref ?? 'bundle_edge'),
  };
}

function buildCapabilityBridges(bundle: KnowledgeBundle, nodeMap: Map<string, RouteNode>, route: ResolvedRoute, threatIds: Set<string>, defenseIds: Set<string>) {
  const bridges: CapabilityBridge[] = [];
  const candidateEdges = bundle.edges.filter((edge) => (threatIds.has(edge.source) || defenseIds.has(edge.source)) && defenseIds.has(edge.target));
  for (const edge of [...route.edges, ...candidateEdges]) {
    const sourceType = nodeMap.get(edge.source)?.type;
    const targetType = nodeMap.get(edge.target)?.type;
    const relationship = bridgeRelationship(edge.relationship, sourceType, targetType);
    if (!relationship) continue;
    bridges.push({
      source: edge.source,
      target: edge.target,
      relationship,
      confidence: edge.confidence ?? 'derived_from_bundle',
      source_ref: sanitizeSourceRef(edge.source_ref ?? 'bundle_edge'),
    });
  }
  for (const attackId of [...threatIds].filter((id) => nodeMap.get(id)?.type === 'attack')) {
    const record = bundle.coverage?.[attackId];
    for (const detection of record?.detections ?? []) {
      if (defenseIds.has(detection)) bridges.push({ source: attackId, target: detection, relationship: 'should_be_detected_by', confidence: 'derived_from_bundle', source_ref: 'bundle_derived' });
    }
    for (const evidence of record?.evidence ?? []) {
      if (defenseIds.has(evidence)) bridges.push({ source: attackId, target: evidence, relationship: 'requires_evidence', confidence: 'derived_from_bundle', source_ref: 'bundle_derived' });
    }
  }
  return dedupeBridgeRecords(bridges);
}

function bridgeRelationship(relationship: string, sourceType?: NodeType, targetType?: NodeType) {
  if (sourceType === 'd3fend' && targetType === 'control' && ['implemented_by', 'protected_by_control'].includes(relationship)) return 'implemented_by_control';
  if (sourceType === 'control' && targetType === 'detection' && ['enables_detection', 'validated_by_detection'].includes(relationship)) return 'validated_by_detection';
  if (sourceType === 'detection' && targetType === 'evidence' && relationship === 'requires_evidence') return 'requires_evidence';
  if (sourceType === 'evidence' && targetType === 'gap' && relationship === 'missing_evidence_creates_gap') return 'missing_evidence_creates_gap';
  if (sourceType === 'gap' && targetType === 'action' && relationship === 'closed_by_action') return 'closed_by_action';
  return '';
}

function isDefenseRelationship(relationship: string) {
  return ['implemented_by', 'protected_by_control', 'enables_detection', 'validated_by_detection', 'requires_evidence', 'missing_evidence_creates_gap', 'closed_by_action'].includes(relationship);
}

function dedupeBridgeRecords(bridges: CapabilityBridge[]) {
  const seen = new Set<string>();
  return bridges.filter((bridge) => {
    const key = `${bridge.source}|${bridge.relationship}|${bridge.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function resolveThreatStatus(inputType: NodeType, sections: CapabilitySection[], bridges: CapabilityBridge[]) {
  const present = new Set(sections.filter((section) => section.nodes.length > 0).map((section) => section.type));
  const expected = expectedThreatTypes(inputType);
  if (!present.size) return 'unresolved';
  if (expected.length && expected.every((type) => present.has(type))) return 'complete';
  if (present.size === 1 && !bridges.length) return 'catalog-only';
  return 'partial';
}

function resolveDefenseStatus(sections: CapabilitySection[], threatNodes: RouteNode[]) {
  const count = (type: NodeType) => sections.find((section) => section.type === type)?.nodes.length ?? 0;
  if (!defenseMapTypes.some((type) => count(type))) return 'unresolved';
  if (count('control') && count('detection') && count('evidence') && count('action') && count('action') >= count('gap')) return 'ready';
  if (threatNodes.some((node) => node.type === 'attack') && !count('detection')) return 'detection-gap';
  if (count('detection') && !count('evidence')) return 'evidence-gap';
  if (count('gap') && count('action') < count('gap')) return 'action-gap';
  return 'partial-defense';
}

function resolveCapabilityPriority(threatNodes: RouteNode[], sections: CapabilitySection[]) {
  const count = (type: NodeType) => sections.find((section) => section.type === type)?.nodes.length ?? 0;
  const hasThreat = threatNodes.length > 0;
  const hasAttack = threatNodes.some((node) => node.type === 'attack');
  const hasDefense = defenseMapTypes.some((type) => count(type));
  let final = 'medium';
  if (!hasThreat) final = 'unknown';
  else if (hasThreat && !hasDefense) final = 'high';
  else if (hasAttack && !count('detection')) final = 'high';
  else if (count('detection') && !count('evidence')) final = 'medium';
  else if (count('gap') && count('action') < count('gap')) final = 'medium';
  else if (count('evidence') && (count('control') || count('detection') || count('action'))) final = 'low';
  return {
    threat_relevance: hasThreat ? 'known' : 'unknown',
    exposure: threatNodes.some((node) => Boolean(node.metadata?.product || node.metadata?.product_family)) ? 'known' : 'unknown',
    defense_gap: final,
    final_priority: final,
    rationale: 'Priority derived from bundle coverage only. GTI enrichment not applied.',
    rationale_es: priorityRationaleEs(final),
  };
}

function resolveCapabilityConfidence(edges: RouteEdge[], threatStatus: string, defenseStatus: string) {
  if (threatStatus === 'unresolved') return 'low';
  if (edges.some((edge) => edge.confidence?.startsWith('internal_') || edge.confidence === 'curated')) return defenseStatus === 'ready' || defenseStatus === 'partial-defense' ? 'high' : 'medium';
  return edges.length ? 'medium' : 'low';
}

function collectCapabilitySourceRefs(nodes: RouteNode[], edges: RouteEdge[], bridges: CapabilityBridge[]) {
  const refs = new Set<string>();
  nodes.map(nodeSourceRef).forEach((ref) => refs.add(ref));
  edges.map((edge) => sanitizeSourceRef(edge.source_ref ?? '')).forEach((ref) => refs.add(ref));
  bridges.map((bridge) => sanitizeSourceRef(bridge.source_ref)).forEach((ref) => refs.add(ref));
  return [...refs].filter((ref) => ref && ref !== 'missing_source_ref').sort();
}

function buildRecommendedActionsEs(sections: CapabilitySection[], priority: CapabilityView['priority']): RecommendedAction[] {
  const actions = sections.find((section) => section.type === 'action')?.nodes ?? [];
  const gaps = sections.find((section) => section.type === 'gap')?.nodes ?? [];
  if (actions.length) {
    return actions.slice(0, 5).map((action) => ({
      id: action.id,
      type: 'action',
      description_es: `Ejecutar ${action.id}: ${action.name}. Validar cierre con evidencia operacional antes de declarar cobertura.`,
      owner_guidance_es: 'SOC coordina la validación; AppSec o Infra ejecuta según el activo y control asociado.',
      source_ref: action.sourceRef,
      related_gap_id: gaps[0]?.id ?? '',
    }));
  }
  if (gaps.length) {
    return [{
      id: 'ACTION-VALIDATE-GAPS',
      type: 'action',
      description_es: 'Validar los gaps reportados y definir una acción de cierre con owner y evidencia verificable.',
      owner_guidance_es: 'SOC debe coordinar la validación; AppSec o Infra debe ejecutar el cierre según el dominio afectado.',
      source_ref: 'bundle_derived',
      related_gap_id: gaps[0].id,
    }];
  }
  if (priority.final_priority === 'high') {
    return [{
      id: 'ACTION-CREATE-DEFENSE-COVERAGE',
      type: 'action',
      description_es: 'Crear cobertura defensiva mínima: Control, Detection y Evidence para la ruta de amenaza encontrada.',
      owner_guidance_es: 'SOC define la Detection; Infra o AppSec confirma Control y Evidence disponibles.',
      source_ref: 'bundle_derived',
      related_gap_id: '',
    }];
  }
  return [];
}

function buildExecutiveSummaryEs(threatStatus: string, defenseStatus: string, priority: string) {
  return `Attack2Defend resolvió la consulta con Threat Route '${threatStatus}' y Defense Readiness '${defenseStatus}'. La prioridad operativa inicial es '${priority}' y se deriva solo del bundle local.`;
}

function buildDecisionContextEs(threatSections: CapabilitySection[], defenseSections: CapabilitySection[]) {
  const threatCount = threatSections.reduce((sum, section) => sum + section.nodes.length, 0);
  const defenseCount = defenseSections.reduce((sum, section) => sum + section.nodes.length, 0);
  return `La vista separa ${threatCount} nodos de amenaza y ${defenseCount} nodos operativos. El resultado conserva trazabilidad portable para revisión y automatización sin llamadas públicas desde la UI.`;
}

function buildRiskRationaleEs(priority: CapabilityView['priority'], sections: CapabilitySection[]) {
  const detections = sections.find((section) => section.type === 'detection')?.nodes.length ?? 0;
  const evidence = sections.find((section) => section.type === 'evidence')?.nodes.length ?? 0;
  const gaps = sections.find((section) => section.type === 'gap')?.nodes.length ?? 0;
  if (priority.final_priority === 'high') return 'La prioridad es alta porque existe ruta de amenaza sin cobertura defensiva suficiente en el bundle.';
  if (detections && !evidence) return 'La prioridad es media porque hay Detection, pero falta Evidence verificable para sostener la decisión.';
  if (gaps) return 'La prioridad es media porque el bundle declara gaps que requieren validación y acción de cierre.';
  return 'La prioridad es baja o desconocida según la cobertura local disponible; no se aplicó enriquecimiento GTI.';
}

function buildGapExplanationEs(sections: CapabilitySection[]) {
  const gaps = sections.find((section) => section.type === 'gap')?.nodes ?? [];
  if (gaps.length) return `El bundle declara gaps operativos que deben cerrarse con evidencia: ${gaps.slice(0, 4).map((gap) => gap.name).join('; ')}.`;
  return 'No hay gaps defensivos declarados para esta ruta en el bundle local.';
}

function priorityRationaleEs(priority: string) {
  if (priority === 'high') return 'Prioridad alta: hay amenaza localmente relacionada y falta cobertura defensiva verificable.';
  if (priority === 'medium') return 'Prioridad media: existe cobertura parcial, pero faltan segmentos o evidencia para cerrar la decisión.';
  if (priority === 'low') return 'Prioridad baja: el bundle contiene cobertura defensiva con evidencia o acción asociada.';
  return 'Prioridad desconocida: el bundle no contiene una ruta suficiente para priorizar.';
}

function expectedThreatTypes(inputType: NodeType): NodeType[] {
  if (inputType === 'cve') return ['cve', 'cwe', 'capec', 'attack', 'd3fend'];
  if (inputType === 'cwe') return ['cwe', 'capec', 'attack', 'd3fend'];
  if (inputType === 'capec') return ['capec', 'attack', 'd3fend'];
  if (inputType === 'attack') return ['attack', 'd3fend'];
  if (inputType === 'd3fend') return ['d3fend'];
  return [];
}

function missingThreatSegments(inputType: NodeType, sections: CapabilitySection[]) {
  const present = new Set(sections.filter((section) => section.nodes.length > 0).map((section) => section.type));
  return expectedThreatTypes(inputType).filter((type) => !present.has(type as NodeType));
}

function missingDefenseSegments(sections: CapabilitySection[]) {
  return defenseMapTypes.filter((type) => {
    const count = sections.find((section) => section.type === type)?.nodes.length ?? 0;
    if (type === 'gap') return false;
    return count === 0;
  });
}

function defenseEmptyMessage(type: NodeType, hasThreat: boolean) {
  if (type === 'detection') return hasThreat ? 'Existe ruta de amenaza, pero no hay Detection vinculada en el bundle. Se requiere validar regla SIEM, query de hunting o caso de uso asociado.' : 'No hay Detection vinculada.';
  if (type === 'evidence') return 'Existe intención defensiva, pero no hay Evidence suficiente para demostrar cobertura operacional en SIEM.';
  if (type === 'action') return 'Hay brecha defensiva, pero no hay acción de cierre modelada.';
  if (type === 'control') return 'No hay Control modelado para esta ruta; se requiere confirmar contramedida aplicable.';
  if (type === 'gap') return 'No hay Gap explícito; si falta evidencia, debe declararse antes de cerrar cobertura.';
  return 'Segmento operativo no disponible.';
}

function officialLinkForNode(node: RouteNode) {
  if (node.type === 'cve') return node.url || `https://www.cve.org/CVERecord?id=${node.id}`;
  if (node.type === 'cwe') return `https://cwe.mitre.org/data/definitions/${node.id.replace('CWE-', '')}.html`;
  if (node.type === 'capec') return `https://capec.mitre.org/data/definitions/${node.id.replace('CAPEC-', '')}.html`;
  if (node.type === 'attack') return `https://attack.mitre.org/techniques/${node.id.replace('.', '/')}/`;
  if (node.type === 'd3fend') return `https://d3fend.mitre.org/technique/${node.id}/`;
  return '';
}

function nodeSourceRef(node: RouteNode) {
  const metadata = node.metadata ?? {};
  return sanitizeSourceRef(firstString(metadata.source_ref) || firstString(metadata.mapping_file) || firstString(metadata.source) || 'missing_source_ref');
}

function sanitizeMetadata(metadata?: Record<string, unknown>): Record<string, unknown> {
  return sanitizeAny(metadata ?? {}) as Record<string, unknown>;
}

function sanitizeAny(value: unknown, key = ''): unknown {
  if (Array.isArray(value)) return value.map((item) => sanitizeAny(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([itemKey, itemValue]) => [itemKey, sanitizeAny(itemValue, itemKey)]));
  if (typeof value !== 'string') return value;
  if (['url', 'official_link'].includes(key)) return value;
  if (['source_ref', 'mapping_file', 'source'].includes(key) || containsLocalPathLeak(value)) return sanitizeSourceRef(value);
  return value;
}

function sanitizeSourceRef(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) return 'missing_source_ref';
  const text = value.trim();
  if (text.startsWith('http://') || text.startsWith('https://')) return text;
  if (['bundle_derived', 'bundle_edge', 'missing_source_ref'].includes(text) || ['baseline:', 'coverage:', 'curated:', 'generated:', 'galeax_', 'mitre_'].some((prefix) => text.startsWith(prefix)) || ['nvd_api', 'cisa_kev'].includes(text)) return text;
  const normalized = text.split('\\').join('/');
  const mappingMatch = normalized.match(/(data\/mappings\/[^\s:;,'")]+\.json)/i);
  if (mappingMatch) return mappingMatch[1];
  const repoMatch = normalized.match(/(?:^|\/)attack2defend\/(.+)$/i);
  if (repoMatch && !containsLocalPathLeak(repoMatch[1])) return repoMatch[1];
  if (containsLocalPathLeak(normalized)) return 'sanitized:unknown_source_ref';
  if (normalized.toLowerCase().startsWith('data/mappings/')) return normalized;
  return text;
}

function containsLocalPathLeak(value: string) {
  const lowered = value.split('\\').join('/').toLowerCase();
  return ['/home/', '/users/', '/private/', '/var/folders/'].some((marker) => lowered.includes(marker)) || /\b[a-z]:\//.test(lowered);
}

function firstString(value: unknown) {
  return typeof value === 'string' ? value : '';
}

function isThreatEdge(edge: RouteEdge, nodeMap: Map<string, RouteNode>) {
  const sourceType = nodeMap.get(edge.source)?.type;
  const targetType = nodeMap.get(edge.target)?.type;
  return Boolean(sourceType && targetType && threatMapTypes.includes(sourceType) && threatMapTypes.includes(targetType));
}

function statusTone(status: string): CoverageStatus {
  if (['ready', 'complete', 'low'].includes(status)) return 'covered';
  if (['partial', 'partial-defense', 'catalog-only', 'medium'].includes(status)) return 'partial';
  if (['detection-gap', 'evidence-gap', 'action-gap', 'high'].includes(status)) return 'missing';
  return 'unknown';
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

function isCpeNode(node: RouteNode){ const m=node.metadata as Record<string,unknown>|undefined; return node.id.startsWith('CPE:2.3') || m?.framework==='cpe'; }
function CpePanel({node,bundle,onSelect}:{node:RouteNode;bundle:KnowledgeBundle;onSelect:(id:string)=>void}){ const m=(node.metadata??{}) as Record<string,unknown>; const related=(bundle.indexes?.cpe_to_cve as Record<string,string[]>|undefined)?.[node.id]??[]; return <div><h4>CPE/Product</h4><p>{String(m.vendor??'unknown')} / {String(m.product??'unknown')} / {String(m.version??'*')}</p><code>{node.id}</code><p>{related.length} CVEs relacionadas</p>{related.map((cve)=><button key={cve} className='secondary-button' onClick={()=>onSelect(cve)}>{cve}</button>)}</div>; }
function KevPanel({node,bundle}:{node:RouteNode;bundle:KnowledgeBundle}){ const kev=(bundle.indexes?.kev as Record<string,Record<string,unknown>>|undefined)?.[node.id]; if(!kev) return null; return <div className='kev-badge'><strong>KEV</strong><p>{String(kev.required_action??'required_action n/a')}</p><small>{String(kev.vendor??'')} {String(kev.product??'')} {String(kev.date_added??'')}</small></div>; }
function MultiSelectionSummary({selectedIds,activeRoute}:{selectedIds:string[];activeRoute:ResolvedRoute}){ if(selectedIds.length<2) return null; return <p>Multi-ID: {selectedIds.join(', ')} · nodos compartidos potenciales: {activeRoute.nodes.length}</p>; }

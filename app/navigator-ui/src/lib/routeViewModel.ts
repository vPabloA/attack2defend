import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import { buildAiContextPacket, type AiAssistTask } from '../graph/aiContextPacket';
import { CANONICAL_CHAIN_LABEL, buildCanonicalChain } from '../graph/canonicalChain';
import { filterEdgesByVisibleNodes, filterNodesByScope, type GraphFilters, type GraphScope } from '../graph/graphFilters';
import { graphNodeLabel, graphRelationshipLabel } from '../graph/graphSemantics';
import { missingSourceRef } from '../types/provenance';
import { resolveSearchSelection } from './a2dSearchHelpers.js';

export type RouteLayer =
  | 'cve'
  | 'cwe'
  | 'capec'
  | 'attack'
  | 'd3fend'
  | 'control'
  | 'detection'
  | 'evidence'
  | 'gap'
  | 'action';

export type ConfidenceBadge =
  | 'official'
  | 'analytical_inferred'
  | 'baseline'
  | 'conditional'
  | 'post_exploitation'
  | 'unknown';

export interface RouteViewNode {
  id: string;
  label: string;
  layer: RouteLayer;
  subtitle?: string;
  description?: string;
  badge?: ConfidenceBadge;
  sourceKind?: string;
  provenance?: string[];
  warnings?: string[];
}

export interface RouteViewEdge {
  id: string;
  source: string;
  target: string;
  badge?: ConfidenceBadge;
  relationship?: string;
  isPrimary?: boolean;
  isConditional?: boolean;
  isInferred?: boolean;
}

export interface Tier1Readout {
  title: string;
  bullets: string[];
  summary?: string;
  severity?: string;
  cvss?: string | number | Record<string, unknown> | null;
  vector?: string;
  confidence?: string;
  provenance?: string;
  review_status?: 'approved' | 'candidate' | 'pending' | 'rejected';
  mode?: 'cve' | 'node' | 'fallback';
  associated_cves?: string[];
  attack_techniques?: Array<{ id: string; name: string; justification?: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  d3fend_controls?: Array<{ id: string; name: string; justification: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  compensating_controls?: Array<{ id: string; label: string; text: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  detection_guidance?: Array<{ id: string; label: string; text: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  evidence_to_review?: Array<{ id: string; label: string; text: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  gaps?: Array<{ id: string; label: string; text: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  risk_acceptance_matrix?: Array<{ id: string; label: string; minimum_controls: string[]; rationale: string; provenance?: string; confidence?: string; review_status?: 'approved' | 'candidate' | 'pending' | 'rejected' }>;
  copy_paste_10_lines?: string[];
  checklist?: string[];
  escalation_criteria?: string[];
  source_ref?: string;
  soc_action_pack?: Record<string, unknown>;
}

export interface CoherenceItem {
  layer: RouteLayer | 'summary';
  label: string;
  reading: string;
  badge?: ConfidenceBadge;
}

export interface RouteViewModel {
  query: string;
  found: boolean;
  isPreview: boolean;
  sourceMode: 'bundle' | 'preview';
  canonicalPath: RouteViewNode[];
  nodes: RouteViewNode[];
  edges: RouteViewEdge[];
  tier1Readout: Tier1Readout;
  coherence: CoherenceItem[];
  quickContext: Record<string, string>;
  warnings: string[];
}

export interface PreviewRouteNode {
  id: string;
  type: RouteLayer;
  name: string;
  description?: string;
  url?: string;
}

export interface PreviewRouteEdge {
  source: string;
  target: string;
  relationship: string;
  confidence?: string;
  source_ref?: string;
}

export interface CoverageRecord {
  status?: string;
  controls?: string[];
  detections?: string[];
  evidence?: string[];
  gaps?: string[];
}

export interface PreviewRouteArtifact {
  artifact_type: 'attack2defend.preview_route';
  canonical: false;
  input: string;
  normalized_input: string;
  generated_at: string;
  source: 'mock' | 'api';
  nodes: PreviewRouteNode[];
  edges: PreviewRouteEdge[];
  coverage?: Record<string, CoverageRecord>;
  warnings: string[];
  provenance: Array<{
    id: string;
    source: string;
    trust: 'official' | 'inferred' | 'mock' | 'unknown';
    note?: string;
  }>;
}

export function deriveConfidenceBadge(input: {
  sourceKind?: string;
  relationship?: string;
  deterministic?: boolean;
  inferred?: boolean;
  basis?: string;
  status?: string;
  tactic?: string;
  technique?: string;
  layer?: string;
}): ConfidenceBadge {
  const sourceKind = (input.sourceKind ?? '').toLowerCase();
  const basis = (input.basis ?? '').toLowerCase();
  const relationship = (input.relationship ?? '').toLowerCase();
  const status = (input.status ?? '').toLowerCase();
  const technique = (input.technique ?? '').toLowerCase();

  if (sourceKind.includes('official') || sourceKind.includes('mitre') || sourceKind.includes('nvd') || sourceKind.includes('cna')) return 'official';
  if (input.deterministic === false || input.inferred || basis.includes('inferred') || relationship.includes('inferred')) return 'analytical_inferred';
  if (basis.includes('baseline') || sourceKind.includes('baseline') || sourceKind.includes('public-compatible')) return 'baseline';
  if (status.includes('conditional') || relationship.includes('conditional') || sourceKind.includes('conditional')) return 'conditional';
  if (technique.startsWith('t1') && (relationship.includes('post') || status.includes('post'))) return 'post_exploitation';
  return 'unknown';
}

export function buildTier1Readout(params: {
  bundle: KnowledgeBundle;
  selectedNode: RouteNode | null;
  routeNodes: RouteNode[];
  routeEdges: RouteEdge[];
  viewNodes: RouteViewNode[];
  warnings?: string[];
}): Tier1Readout {
  const selectedNode = params.selectedNode;
  const fallbackBullets = [
    'Ruta de conocimiento disponible para análisis.',
    'Validar exposición real del activo afectado.',
    'Revisar controles D3FEND sugeridos.',
    'Confirmar evidencia antes de escalar.',
  ];
  if (!selectedNode) {
    return {
      title: 'Tier 1 Analyst Readout',
      bullets: fallbackBullets,
      summary: 'Sin nodo seleccionado en el bundle local.',
      confidence: 'unknown',
      provenance: 'unknown',
      mode: 'fallback',
      copy_paste_10_lines: fallbackBullets,
      checklist: [
        'Confirmar un identificador cargado en el bundle.',
        'Verificar que el bundle local incluya rutas y reverse index.',
        'Revisar el estado de sincronización del bundle.',
      ],
      escalation_criteria: ['No hay nodo activo en la vista.'],
      associated_cves: [],
      attack_techniques: [],
      d3fend_controls: [],
      compensating_controls: [],
      detection_guidance: [],
      evidence_to_review: [],
      gaps: [],
      risk_acceptance_matrix: [],
    };
  }

  const activeNode = selectedNode as RouteNode;
  const cveRecord = params.bundle.cves?.[activeNode.id];
  const reverseSelection = resolveSearchSelection(params.bundle, activeNode.id, { maxRoots: 8, maxReverseMatches: 8 });
  const associatedCves = uniqueStrings(
    cveRecord?.tier1_readout?.associated_cves ??
      reverseSelection.associatedCves ??
      (activeNode.type === 'cve' ? [activeNode.id] : []),
  );
  const primaryCveRecord = cveRecord ?? (associatedCves.length ? params.bundle.cves?.[associatedCves[0]] : undefined);
  const pack = primaryCveRecord?.soc_action_pack ?? buildFallbackSocActionPack(params, activeNode, associatedCves);
  const readout: Partial<Tier1Readout> = primaryCveRecord?.tier1_readout ?? {};
  const bullets = (readout.bullets?.length ? readout.bullets : buildBullets(activeNode, params.routeNodes, params.warnings, associatedCves)).slice(0, 5);
  const summary = readout.summary ?? primaryCveRecord?.description ?? activeNode.description ?? `Nodo ${activeNode.id} disponible en el bundle local.`;
  const severity = primaryCveRecord?.severity ?? readout.severity ?? (activeNode.type === 'cve' ? 'unknown' : 'informational');
  const confidence = primaryCveRecord?.confidence ?? readout.confidence ?? (activeNode.type === 'cve' ? 'unknown' : 'medium');
  const provenance = primaryCveRecord?.provenance ?? readout.provenance ?? (activeNode.type === 'cve' ? 'canonical' : 'derived');
  const reviewStatus = primaryCveRecord?.review_status ?? readout.review_status ?? (primaryCveRecord ? 'approved' : 'candidate');
  const associatedReadoutCves = uniqueStrings(readout.associated_cves ?? associatedCves);
  const detectionGuidance = pack.detection_rules ?? readout.detection_guidance ?? [];
  const evidence = pack.evidence_to_review ?? readout.evidence_to_review ?? [];
  const gaps = pack.gaps ?? readout.gaps ?? [];
  const readoutCopy = (readout.copy_paste_10_lines?.length ? readout.copy_paste_10_lines : buildCopyPasteLines({
    node: activeNode,
    severity,
    confidence,
    primaryAttack: pack.attack_techniques?.[0]?.id ?? reverseSelection.hits.find((hit) => hit.type === 'attack')?.token ?? 'unknown',
    d3fendControls: pack.d3fend_controls,
    evidence,
    compensatingControls: pack.compensating_controls,
    detectionGuidance,
    gaps,
    riskAcceptance: pack.risk_acceptance_matrix,
  })).slice(0, 10);

  return {
    title: `Tier 1 Analyst Readout · ${activeNode.id}`,
    bullets,
    summary,
    severity,
    cvss: primaryCveRecord?.cvss ?? readout.cvss ?? null,
    vector: readout.vector ?? vectorFromCvss(primaryCveRecord?.cvss),
    confidence,
    provenance,
    review_status: reviewStatus,
    mode: activeNode.type === 'cve' ? 'cve' : 'node',
    associated_cves: associatedReadoutCves,
    attack_techniques: pack.attack_techniques ?? readout.attack_techniques ?? [],
    d3fend_controls: pack.d3fend_controls ?? readout.d3fend_controls ?? [],
    compensating_controls: pack.compensating_controls ?? readout.compensating_controls ?? [],
    detection_guidance: detectionGuidance,
    evidence_to_review: evidence,
    gaps,
    risk_acceptance_matrix: pack.risk_acceptance_matrix ?? readout.risk_acceptance_matrix ?? [],
    copy_paste_10_lines: readoutCopy,
    checklist: (readout.checklist?.length ? readout.checklist : buildChecklist(activeNode, severity, confidence, associatedReadoutCves, gaps)).slice(0, 8),
    escalation_criteria: (readout.escalation_criteria?.length ? readout.escalation_criteria : buildEscalationCriteria(activeNode, gaps, detectionGuidance, evidence)).slice(0, 6),
    source_ref: activeNode.metadata?.source_ref ? String(activeNode.metadata.source_ref) : undefined,
    soc_action_pack: pack,
  };
}

function buildFallbackSocActionPack(params: {
  bundle: KnowledgeBundle;
  selectedNode: RouteNode | null;
  routeNodes: RouteNode[];
  routeEdges: RouteEdge[];
  viewNodes: RouteViewNode[];
  warnings?: string[];
}, selectedNode: RouteNode, associatedCves: string[]) {
  const d3Nodes = params.routeNodes.filter((node) => node.type === 'd3fend').slice(0, 3);
  const attackNodes = params.routeNodes.filter((node) => node.type === 'attack').slice(0, 3);
  const gaps = [
    {
      id: `GAP-${selectedNode.id}-PACK`,
      label: 'Route gap',
      text: selectedNode.type === 'cve' ? `No se ha cargado un soc_action_pack canonical para ${selectedNode.id}.` : `No existe pack canónico directo para ${selectedNode.id}.`,
      provenance: 'inferred',
      confidence: 'medium',
      review_status: 'candidate' as const,
    },
    ...((params.warnings ?? []).slice(0, 2).map((warning, index) => ({
      id: `GAP-${selectedNode.id}-WARN-${index + 1}`,
      label: 'Route gap',
      text: warning,
      provenance: 'inferred',
      confidence: 'medium',
      review_status: 'candidate' as const,
    }))),
  ];
  return {
    attack_techniques: attackNodes.map((node) => ({
      id: node.id,
      name: node.name,
      justification: `Técnica asociada a la ruta visible para ${selectedNode.id}.`,
      provenance: 'derived',
      confidence: 'medium',
      review_status: 'candidate' as const,
    })),
    d3fend_controls: d3Nodes.map((node) => ({
      id: node.id,
      name: node.name,
      justification: `Control defensivo visible en la ruta del bundle local para ${selectedNode.id}.`,
      provenance: 'derived',
      confidence: 'medium',
      review_status: 'candidate' as const,
    })),
    compensating_controls: [
      {
        id: `COMP-${selectedNode.id}-PATCH`,
        label: 'Patch/Upgrade',
        text: `Revisar parches y versionado aplicado a ${selectedNode.id}.`,
        provenance: 'inferred',
        confidence: 'medium',
        review_status: 'candidate' as const,
      },
    ],
    detection_rules: [
      {
        id: `DETECT-${selectedNode.id}-01`,
        label: 'Monitoring',
        text: `Revisar telemetría asociada a ${selectedNode.id} y a sus técnicas relacionadas.`,
        provenance: 'inferred',
        confidence: 'medium',
        review_status: 'candidate' as const,
      },
    ],
    evidence_to_review: [
      {
        id: `EVID-${selectedNode.id}-01`,
        label: 'Evidence',
        text: `Corroborar eventos y artefactos ligados a ${selectedNode.id}.`,
        provenance: 'inferred',
        confidence: 'medium',
        review_status: 'candidate' as const,
      },
    ],
    ioc_candidates: [
      {
        id: `IOC-${selectedNode.id}-01`,
        label: 'IOC candidate',
        text: associatedCves.length ? associatedCves.join(', ') : selectedNode.id,
        provenance: 'inferred',
        confidence: 'low',
        review_status: 'candidate' as const,
      },
    ],
    gaps,
    risk_acceptance_matrix: [
      {
        id: `RISK-${selectedNode.id}-01`,
        label: 'Minimal acceptance',
        minimum_controls: ['Patch/Upgrade', 'Monitoring', 'Exposure review'],
        rationale: `Escenario provisional mientras no exista pack canónico para ${selectedNode.id}.`,
        provenance: 'inferred',
        confidence: 'medium',
        review_status: 'candidate' as const,
      },
    ],
  };
}

function buildBullets(selectedNode: RouteNode, routeNodes: RouteNode[], warnings: string[] | undefined, associatedCves: string[]): string[] {
  const bullets: string[] = [];
  if (selectedNode.description?.trim()) bullets.push(selectedNode.description.trim());
  bullets.push(`Nodo activo: ${selectedNode.id}.`);
  if (associatedCves.length) bullets.push(`CVEs asociados: ${associatedCves.slice(0, 5).join(', ')}.`);
  const d3 = routeNodes.filter((node) => node.type === 'd3fend').slice(0, 2);
  if (d3.length) bullets.push(`Controles D3FEND visibles: ${d3.map((node) => node.name).join(', ')}.`);
  if (warnings?.length) bullets.push(...warnings.slice(0, 2));
  return bullets.length ? bullets : ['Ruta de conocimiento disponible para análisis.'];
}

function buildCopyPasteLines(params: {
  node: RouteNode;
  severity: string;
  confidence: string;
  primaryAttack: string;
  d3fendControls: Array<{ id: string; name: string }>;
  evidence: Array<{ id: string; label: string; text: string }>;
  compensatingControls: Array<{ id: string; label: string; text: string }>;
  detectionGuidance: Array<{ id: string; label: string; text: string }>;
  gaps: Array<{ id: string; label: string; text: string }>;
  riskAcceptance: Array<{ id: string; label: string; minimum_controls: string[]; rationale: string }>;
}) {
  return [
    `CVE: ${params.node.id}`,
    `Severity: ${params.severity}`,
    `Likely ATT&CK: ${params.primaryAttack}`,
    `Defensive mapping: ${params.d3fendControls.slice(0, 3).map((item) => item.id).join(', ') || 'n/a'}`,
    `Evidence to review: ${params.evidence.slice(0, 2).map((item) => item.text).join(' | ') || 'n/a'}`,
    `Compensating controls: ${params.compensatingControls.slice(0, 2).map((item) => item.text).join(' | ') || 'n/a'}`,
    `Detection guidance: ${params.detectionGuidance.slice(0, 2).map((item) => item.text).join(' | ') || 'n/a'}`,
    `Known gaps: ${params.gaps.slice(0, 2).map((item) => item.text).join(' | ') || 'n/a'}`,
    `Escalate if: ${params.gaps.length ? params.gaps[0].text : 'validation remains incomplete'}`,
    `Risk acceptance: ${params.riskAcceptance.slice(0, 1).map((item) => item.rationale).join(' | ') || 'n/a'}`,
  ];
}

function buildChecklist(selectedNode: RouteNode, severity: string, confidence: string, associatedCves: string[], gaps: Array<{ id: string; label: string; text: string }>) {
  const items = [
    `Confirmar el activo relacionado con ${selectedNode.id}.`,
    `Revisar severidad ${severity} y confianza ${confidence}.`,
    associatedCves.length ? `Validar CVEs asociados: ${associatedCves.slice(0, 3).join(', ')}.` : `Validar si ${selectedNode.id} tiene relaciones en el bundle.`,
    gaps.length ? `Cerrar brechas descritas: ${gaps[0].text}` : 'Documentar ausencia de brechas explícitas.',
  ];
  return items;
}

function buildEscalationCriteria(
  selectedNode: RouteNode,
  gaps: Array<{ id: string; label: string; text: string }>,
  detectionGuidance: Array<{ id: string; label: string; text: string }>,
  evidence: Array<{ id: string; label: string; text: string }>,
) {
  const criteria = [
    `No hay evidencia suficiente para confirmar el estado de ${selectedNode.id}.`,
    gaps.length ? gaps[0].text : 'No se declaran brechas explícitas en el bundle local.',
    detectionGuidance.length ? `Falta validar: ${detectionGuidance[0].text}` : 'No existe orientación de monitoreo directa.',
    evidence.length ? `Falta corroborar: ${evidence[0].text}` : 'No hay evidencia mínima asociada.',
  ];
  return criteria;
}

function vectorFromCvss(cvss: unknown): string | undefined {
  if (cvss && typeof cvss === 'object' && !Array.isArray(cvss) && 'vector' in cvss && typeof (cvss as Record<string, unknown>).vector === 'string') {
    return String((cvss as Record<string, unknown>).vector);
  }
  if (cvss && typeof cvss === 'object' && !Array.isArray(cvss) && 'vectorString' in cvss && typeof (cvss as Record<string, unknown>).vectorString === 'string') {
    return String((cvss as Record<string, unknown>).vectorString);
  }
  return undefined;
}

function uniqueStrings(values: Array<string | undefined | null>): string[] {
  return [...new Set(values.map((value) => String(value ?? '').trim()).filter(Boolean))];
}

export function buildCoherenceItems(input: {
  selectedNode: RouteNode | null;
  routeNodes: RouteNode[];
  routeEdges: RouteEdge[];
  viewNodes: RouteViewNode[];
}): CoherenceItem[] {
  const items: CoherenceItem[] = [];
  const has = (type: RouteLayer) => input.routeNodes.some((node: RouteNode) => node.type === type);
  items.push({ layer: 'summary', label: 'Resumen', reading: input.selectedNode ? `Ruta activa para ${input.selectedNode.id}.` : 'Sin ruta activa.', badge: input.selectedNode ? 'official' : 'unknown' });
  items.push({ layer: 'cve', label: 'CVE', reading: has('cve') ? 'Vulnerabilidad raíz identificada.' : 'Sin CVE visible en la ruta.', badge: has('cve') ? 'official' : 'unknown' });
  items.push({ layer: 'cwe', label: 'CWE', reading: has('cwe') ? 'Debilidad asociada presente.' : 'Sin CWE visible en la ruta.', badge: has('cwe') ? 'baseline' : 'unknown' });
  items.push({ layer: 'capec', label: 'CAPEC', reading: has('capec') ? 'Patrón ofensivo relacionado.' : 'Sin CAPEC visible en la ruta.', badge: has('capec') ? 'analytical_inferred' : 'unknown' });
  items.push({ layer: 'attack', label: 'ATT&CK', reading: has('attack') ? 'Técnica aplicable bajo condición.' : 'Sin ATT&CK visible en la ruta.', badge: has('attack') ? 'conditional' : 'unknown' });
  items.push({ layer: 'd3fend', label: 'D3FEND', reading: has('d3fend') ? 'Capacidad defensiva accionable.' : 'Sin D3FEND visible en la ruta.', badge: has('d3fend') ? 'official' : 'unknown' });
  return items;
}

export function buildRouteViewModel(params: {
  bundle: KnowledgeBundle;
  query: string;
  selectedIds?: string[];
  filters?: Partial<GraphFilters>;
  aiTask?: AiAssistTask;
}): RouteViewModel {
  const selectedIds = params.selectedIds ?? [];
  const scope = params.filters?.scope ?? 'canonical_chain';
  const nodeMap = new Map(params.bundle.nodes.map((node) => [node.id, node]));
  const selectedNode = selectedIds.length ? nodeMap.get(selectedIds[0]) ?? null : null;
  const activeRoute = selectedIds.length ? resolveRoute(params.bundle, selectedIds) : null;
  const routeNodes = activeRoute ? activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => Boolean(node)) : [];
  const visibleRouteNodes = filterNodesByScope(routeNodes, { scope, ...params.filters });
  const visibleIds = new Set(visibleRouteNodes.map((node) => node.id));
  const visibleRouteEdges = activeRoute ? filterEdgesByVisibleNodes(activeRoute.edges, visibleIds, params.filters?.maxLinks) : [];
  const canonicalChain = buildCanonicalChain(visibleRouteNodes);
  const routeViewNodes = visibleRouteNodes.map((node: RouteNode) => toRouteViewNode(node, params.bundle, visibleRouteEdges));
  const routeViewEdges = visibleRouteEdges.map((edge: RouteEdge) => toRouteViewEdge(edge));
  const warnings = buildWarnings(params.bundle, routeNodes, visibleRouteNodes, visibleRouteEdges, scope);
  const tier1Readout = buildTier1Readout({ bundle: params.bundle, selectedNode, routeNodes, routeEdges: visibleRouteEdges, viewNodes: routeViewNodes, warnings });
  const coherence = buildCoherenceItems({ selectedNode, routeNodes: visibleRouteNodes, routeEdges: visibleRouteEdges, viewNodes: routeViewNodes });
  const aiContextPacket = buildAiContextPacket({ task: params.aiTask, input: params.query, visibleScope: scope, canonicalChain, visibleNodes: visibleRouteNodes, visibleEdges: visibleRouteEdges, bundleVersion: params.bundle.metadata.contract_version ?? params.bundle.metadata.generated_at });
  const bundleVersion = params.bundle.bundle_version ?? params.bundle.metadata.contract_version ?? params.bundle.metadata.generated_at ?? 'unknown';
  const generatedAt = params.bundle.generated_at ?? params.bundle.metadata.generated_at ?? 'unknown';
  const cveCount = Object.keys(params.bundle.cves ?? {}).length || params.bundle.nodes.filter((node) => node.type === 'cve').length;
  const reviewQueueCount = params.bundle.review_queue?.length ?? 0;
  return {
    query: params.query,
    found: Boolean(selectedNode),
    isPreview: false,
    sourceMode: 'bundle',
    canonicalPath: routeViewNodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend'].includes(node.layer)),
    nodes: routeViewNodes,
    edges: routeViewEdges,
    tier1Readout,
    coherence,
    quickContext: {
      bundle_version: bundleVersion,
      generated_at: generatedAt,
      source: params.bundle.source ?? 'CVE2CAPEC',
      provenance: params.bundle.provenance ?? 'canonical',
      cve_count: String(cveCount),
      node_count: String(params.bundle.nodes.length),
      edge_count: String(params.bundle.edges.length),
      route_count: String(params.bundle.routes?.length ?? 0),
      review_queue: String(reviewQueueCount),
      last_sync: params.bundle.generated_at ?? params.bundle.metadata.generated_at ?? 'unknown',
      visible_scope: scope,
      visible_nodes: String(routeViewNodes.length),
      visible_edges: String(routeViewEdges.length),
      selected_mode: selectedNode?.type ?? 'none',
      canonical_chain: CANONICAL_CHAIN_LABEL,
      ai_context_packet: aiContextPacket.capability,
      search_mode: selectedNode ? (selectedNode.type === 'cve' ? 'direct' : 'node') : 'empty',
    },
    warnings,
  };
}

export function buildRouteViewModelFromPreview(artifact: PreviewRouteArtifact): RouteViewModel {
  const routeViewNodes: RouteViewNode[] = artifact.nodes.map((node) => {
    const prov = artifact.provenance.find((p) => p.id === node.id);
    const trust = prov?.trust ?? 'unknown';
    const badge: ConfidenceBadge =
      trust === 'official' ? 'official' :
      trust === 'inferred' ? 'analytical_inferred' :
      trust === 'mock' ? 'conditional' : 'unknown';
    return {
      id: node.id,
      label: graphNodeLabel(node.id, node.name),
      layer: node.type,
      description: node.description,
      badge,
      provenance: [prov?.source ?? 'on-demand-resolution'],
      warnings: trust === 'mock' ? ['Preview — requires validation'] : trust === 'unknown' ? ['Insufficient local evidence'] : [],
    };
  });

  const routeViewEdges: RouteViewEdge[] = artifact.edges.map((edge) => ({
    id: `${edge.source}::${edge.relationship}::${edge.target}`,
    source: edge.source,
    target: edge.target,
    badge: 'analytical_inferred',
    relationship: graphRelationshipLabel(edge.relationship),
    isPrimary: edge.confidence === 'high',
    isConditional: true,
    isInferred: true,
  }));

  const canonicalPath = routeViewNodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend'].includes(node.layer));

  const previewWarnings = [
    'Preview / Not Canonical — generated from on-demand resolution.',
    'Requires validation before operational use.',
    ...artifact.warnings,
  ];

  const selectedViewNode = routeViewNodes.find((n) => n.layer === 'cve') ?? routeViewNodes[0];

  const tier1Readout: Tier1Readout = {
    title: `Tier 1 Preview · ${artifact.normalized_input}`,
    bullets: [
      `Preview route for ${artifact.normalized_input} — not from canonical bundle.`,
      'No CVSS or official description available from local bundle.',
      'Requires analyst validation before escalation.',
      ...previewWarnings.slice(0, 2),
    ].slice(0, 5),
    confidence: 'preview',
  };

  const coherence = buildCoherenceItemsFromView(selectedViewNode, routeViewNodes, routeViewEdges);

  const quickContext: Record<string, string> = {
    source: `on-demand (${artifact.source})`,
    canonical: 'false',
    generated_at: artifact.generated_at,
    node_count: String(routeViewNodes.length),
    edge_count: String(routeViewEdges.length),
    canonical_chain: 'preview',
    status: 'requires_validation',
  };

  return {
    query: artifact.normalized_input,
    found: true,
    isPreview: true,
    sourceMode: 'preview',
    canonicalPath,
    nodes: routeViewNodes,
    edges: routeViewEdges,
    tier1Readout,
    coherence,
    quickContext,
    warnings: previewWarnings,
  };
}

function buildCoherenceItemsFromView(
  selectedNode: RouteViewNode | undefined,
  nodes: RouteViewNode[],
  _edges: RouteViewEdge[],
): CoherenceItem[] {
  const has = (layer: RouteLayer) => nodes.some((n) => n.layer === layer);
  return [
    { layer: 'summary', label: 'Resumen', reading: selectedNode ? `Preview activo para ${selectedNode.id}.` : 'Preview sin nodo raíz.', badge: 'conditional' },
    { layer: 'cve', label: 'CVE', reading: has('cve') ? 'Vulnerabilidad raíz (preview — no canónica).' : 'Sin CVE en preview.', badge: has('cve') ? 'conditional' : 'unknown' },
    { layer: 'cwe', label: 'CWE', reading: has('cwe') ? 'Debilidad inferida (preview).' : 'Sin CWE en preview.', badge: has('cwe') ? 'analytical_inferred' : 'unknown' },
    { layer: 'capec', label: 'CAPEC', reading: has('capec') ? 'Patrón inferido (preview).' : 'Sin CAPEC en preview.', badge: has('capec') ? 'analytical_inferred' : 'unknown' },
    { layer: 'attack', label: 'ATT&CK', reading: has('attack') ? 'Técnica condicional (preview).' : 'Sin ATT&CK en preview.', badge: has('attack') ? 'conditional' : 'unknown' },
    { layer: 'd3fend', label: 'D3FEND', reading: has('d3fend') ? 'Control sugerido (preview).' : 'Sin D3FEND en preview.', badge: has('d3fend') ? 'conditional' : 'unknown' },
  ];
}

function toRouteViewNode(node: RouteNode, bundle: KnowledgeBundle, visibleEdges: RouteEdge[]): RouteViewNode {
  const sourceRef = nodeSourceRef(node);
  const relatedCoverage = bundle.coverage?.[node.id];
  const _confidence = visibleEdges.some((edge) => edge.source === node.id || edge.target === node.id) ? 'high' : 'unknown';
  return {
    id: node.id,
    label: graphNodeLabel(node.id, node.name),
    layer: node.type === 'artifact' ? 'attack' : node.type,
    subtitle: relatedCoverage?.status,
    description: node.description,
    badge: deriveConfidenceBadge({ sourceKind: String(node.metadata?.source_kind ?? ''), basis: String(node.metadata?.source_ref ?? ''), status: relatedCoverage?.status, layer: node.type }),
    sourceKind: String(node.metadata?.source_kind ?? ''),
    provenance: [sourceRef],
    warnings: sourceRef === 'missing_source_ref' ? ['Missing source ref in bundle local'] : [],
  };
}

function toRouteViewEdge(edge: RouteEdge): RouteViewEdge {
  return {
    id: `${edge.source}::${edge.relationship}::${edge.target}`,
    source: edge.source,
    target: edge.target,
    badge: deriveConfidenceBadge({ sourceKind: edge.source_kind, relationship: edge.relationship, inferred: edge.confidence === 'medium' || edge.confidence === 'low', basis: edge.source_ref, status: edge.priority }),
    relationship: graphRelationshipLabel(edge.relationship),
    isPrimary: edge.confidence === 'high',
    isConditional: edge.priority === 'P1' || edge.priority === 'P2',
    isInferred: edge.confidence !== 'high',
  };
}

function resolveRoute(bundle: KnowledgeBundle, roots: string[]) {
  const starts = roots.map((item) => item.toUpperCase()).filter(Boolean);
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const outgoing = new Map<string, RouteEdge[]>();
  for (const edge of bundle.edges) {
    const current = outgoing.get(edge.source) ?? [];
    current.push(edge);
    outgoing.set(edge.source, current);
  }
  const queue: Array<{ id: string; depth: number }> = starts.filter((id) => nodeMap.has(id)).map((id) => ({ id, depth: 0 }));
  const visited = new Set<string>(queue.map((item) => item.id));
  const routeEdges: RouteEdge[] = [];
  while (queue.length) {
    const current = queue.shift();
    if (!current || current.depth >= 5) continue;
    const currentNode = nodeMap.get(current.id);
    if (!currentNode) continue;
    for (const edge of outgoing.get(current.id) ?? []) {
      const nextNode = nodeMap.get(edge.target);
      if (!nextNode) continue;
      if (!(allowedForwardTypeTransitions[currentNode.type] ?? []).includes(nextNode.type)) continue;
      routeEdges.push(edge);
      if (visited.has(nextNode.id)) continue;
      visited.add(nextNode.id);
      queue.push({ id: nextNode.id, depth: current.depth + 1 });
    }
  }
  return { root: starts[0] ?? '', nodes: Array.from(visited), edges: dedupeEdges(routeEdges) };
}

function buildWarnings(bundle: KnowledgeBundle, routeNodes: RouteNode[], visibleNodes: RouteNode[], visibleEdges: RouteEdge[], scope: GraphScope): string[] {
  const warnings: string[] = [];
  if (!routeNodes.length) warnings.push('No active route resolved from the current input.');
  if (visibleNodes.length === 0) warnings.push(`No visible nodes for scope '${scope}'.`);
  if ((bundle.metadata.public_source_failures?.length ?? 0) > 0) warnings.push('Public source failures exist in bundle metadata.');
  const routeIds = new Set(routeNodes.map((node) => node.id));
  const invalidEdges = visibleEdges.filter((edge) => !routeIds.has(edge.source) || !routeIds.has(edge.target));
  if (invalidEdges.length) warnings.push(`${invalidEdges.length} visible edges reference nodes outside the supplied route node set.`);
  return warnings;
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

function nodeSourceRef(node: RouteNode): string {
  return missingSourceRef(node.metadata?.source_ref ?? node.metadata?.mapping_file ?? node.metadata?.source);
}

const allowedForwardTypeTransitions: Partial<Record<RouteNode['type'], RouteNode['type'][]>> = {
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

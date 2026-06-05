import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import { buildAiContextPacket, type AiAssistTask } from '../graph/aiContextPacket';
import { CANONICAL_CHAIN_LABEL, buildCanonicalChain } from '../graph/canonicalChain';
import { filterEdgesByVisibleNodes, filterNodesByScope, type GraphFilters, type GraphScope } from '../graph/graphFilters';
import { graphNodeLabel, graphNodeStatus, graphNodeWeight, graphRelationshipLabel } from '../graph/graphSemantics';
import type { ProvenanceRecord, TrustLevel } from '../types/provenance';
import { canonicalProvenance, missingSourceRef } from '../types/provenance';

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
  severity?: string;
  cvss?: string | number;
  vector?: string;
  confidence?: string;
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
  canonicalPath: RouteViewNode[];
  nodes: RouteViewNode[];
  edges: RouteViewEdge[];
  tier1Readout: Tier1Readout;
  coherence: CoherenceItem[];
  quickContext: Record<string, string>;
  warnings: string[];
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
      confidence: 'unknown',
    };
  }

  const bullets: string[] = [];
  const cveDescription = selectedNode.description?.trim();
  if (cveDescription) bullets.push(cveDescription);
  else bullets.push('No disponible en bundle local para descripción del nodo seleccionado.');
  const coverage = params.bundle.coverage?.[selectedNode.id];
  if (coverage?.gaps?.length) bullets.push(`Requiere validación: ${coverage.gaps[0]}`);
  if (coverage?.status) bullets.push(`Estado de cobertura: ${coverage.status}`);
  const d3 = params.routeNodes.find((node) => node.type === 'd3fend');
  if (d3) bullets.push(`Controles D3FEND disponibles: ${d3.name}`);
  if (params.warnings?.length) bullets.push(...params.warnings.slice(0, 2));
  if (bullets.length === 0) bullets.push(...fallbackBullets);
  return {
    title: `Tier 1 Analyst Readout · ${selectedNode.id}`,
    bullets: bullets.slice(0, 5),
    confidence: coverage?.status ?? 'unknown',
  };
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
  return {
    query: params.query,
    found: Boolean(selectedNode),
    canonicalPath: routeViewNodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend'].includes(node.layer)),
    nodes: routeViewNodes,
    edges: routeViewEdges,
    tier1Readout,
    coherence,
    quickContext: {
      bundle_version: params.bundle.metadata.contract_version ?? params.bundle.metadata.generated_at ?? 'unknown',
      visible_scope: scope,
      route_count: String(params.bundle.routes?.length ?? 0),
      node_count: String(routeViewNodes.length),
      edge_count: String(routeViewEdges.length),
      canonical_chain: CANONICAL_CHAIN_LABEL,
      ai_context_packet: aiContextPacket.capability,
    },
    warnings,
  };
}

function toRouteViewNode(node: RouteNode, bundle: KnowledgeBundle, visibleEdges: RouteEdge[]): RouteViewNode {
  const sourceRef = nodeSourceRef(node);
  const relatedCoverage = bundle.coverage?.[node.id];
  const confidence = visibleEdges.some((edge) => edge.source === node.id || edge.target === node.id) ? 'high' : 'unknown';
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

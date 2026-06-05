import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import type { ProvenanceRecord, TrustLevel } from '../types/provenance';
import { canonicalProvenance, missingSourceRef } from '../types/provenance';
import { buildAiContextPacket, type AiContextPacket, type AiAssistTask } from './aiContextPacket';
import { CANONICAL_CHAIN_LABEL, buildCanonicalChain, canonicalMissingSegments } from './canonicalChain';
import { filterEdgesByVisibleNodes, filterNodesByScope, type GraphFilters, type GraphScope } from './graphFilters';
import { graphNodeLabel, graphNodeStatus, graphNodeWeight, graphRelationshipLabel } from './graphSemantics';

export type GraphNode = {
  id: string;
  label: string;
  type: RouteNode['type'];
  group: RouteNode['type'];
  val: number;
  status: string;
  coverageStatus: string;
  owners: string[];
  sourceRef: string;
  officialLink: string;
  confidenceSummary: string;
  trustLevel: TrustLevel;
  provenance: ProvenanceRecord;
  rawNode: RouteNode;
};

export type GraphLink = {
  source: string;
  target: string;
  relationship: string;
  label: string;
  confidence: string;
  sourceRef: string;
  sourceKind: string;
  trustLevel: TrustLevel;
  provenance: ProvenanceRecord;
  rawEdge: RouteEdge;
};

export type GraphStats = {
  totalNodes: number;
  totalLinks: number;
  canonicalNodes: number;
  threatNodes: number;
  defenseNodes: number;
  gapNodes: number;
  evidenceNodes: number;
  actionNodes: number;
};

export type GraphViewModel = {
  capability: 'attack2defend.graph_view_model';
  principle: typeof CANONICAL_CHAIN_LABEL;
  input: string;
  visibleScope: GraphScope;
  nodes: GraphNode[];
  links: GraphLink[];
  canonicalChain: ReturnType<typeof buildCanonicalChain>;
  defenseExtension: {
    controls: GraphNode[];
    detections: GraphNode[];
    evidence: GraphNode[];
    gaps: GraphNode[];
    actions: GraphNode[];
  };
  stats: GraphStats;
  missingSegments: string[];
  warnings: string[];
  aiContextPacket: AiContextPacket;
};

const DEFAULT_MAX_NODES = 160;
const DEFAULT_MAX_LINKS = 240;

export function buildGraphViewModel(params: {
  bundle: KnowledgeBundle;
  routeNodes: RouteNode[];
  routeEdges: RouteEdge[];
  input: string;
  filters?: Partial<GraphFilters>;
  aiTask?: AiAssistTask;
}): GraphViewModel {
  const scope = params.filters?.scope ?? 'canonical_chain';
  const filters: GraphFilters = {
    scope,
    includeArtifacts: params.filters?.includeArtifacts ?? false,
    nodeTypes: params.filters?.nodeTypes,
    owner: params.filters?.owner,
    maxNodes: params.filters?.maxNodes ?? DEFAULT_MAX_NODES,
    maxLinks: params.filters?.maxLinks ?? DEFAULT_MAX_LINKS,
  };

  const canonicalChain = buildCanonicalChain(params.routeNodes);
  const visibleRouteNodes = filterNodesByScope(params.routeNodes, filters);
  const visibleIds = new Set(visibleRouteNodes.map((node) => node.id));
  const visibleRouteEdges = filterEdgesByVisibleNodes(params.routeEdges, visibleIds, filters.maxLinks);
  const coverage = params.bundle.coverage ?? {};

  const nodes = visibleRouteNodes.map((node) => toGraphNode(node, visibleRouteEdges, coverage));
  const links = visibleRouteEdges.map(toGraphLink);
  const warnings = buildWarnings(params.routeNodes, params.routeEdges, nodes, links, scope);
  const aiContextPacket = buildAiContextPacket({
    task: params.aiTask,
    input: params.input,
    visibleScope: scope,
    canonicalChain,
    visibleNodes: visibleRouteNodes,
    visibleEdges: visibleRouteEdges,
    bundleVersion: params.bundle.metadata.contract_version ?? params.bundle.metadata.generated_at,
  });

  return {
    capability: 'attack2defend.graph_view_model',
    principle: CANONICAL_CHAIN_LABEL,
    input: params.input,
    visibleScope: scope,
    nodes,
    links,
    canonicalChain,
    defenseExtension: {
      controls: nodes.filter((node) => node.type === 'control'),
      detections: nodes.filter((node) => node.type === 'detection'),
      evidence: nodes.filter((node) => node.type === 'evidence'),
      gaps: nodes.filter((node) => node.type === 'gap'),
      actions: nodes.filter((node) => node.type === 'action'),
    },
    stats: buildStats(nodes, links),
    missingSegments: canonicalMissingSegments(canonicalChain).map(String),
    warnings,
    aiContextPacket,
  };
}

function toGraphNode(node: RouteNode, visibleEdges: RouteEdge[], coverage: KnowledgeBundle['coverage']): GraphNode {
  const sourceRef = nodeSourceRef(node);
  const relatedCoverage = coverage?.[node.id];
  const edgeConfidences = visibleEdges
    .filter((edge) => edge.source === node.id || edge.target === node.id)
    .map((edge) => edge.confidence ?? 'unknown');
  const confidenceSummary = edgeConfidences.length ? [...new Set(edgeConfidences)].sort().join(', ') : 'unknown';
  return {
    id: node.id,
    label: graphNodeLabel(node.id, node.name),
    type: node.type,
    group: node.type,
    val: graphNodeWeight(node.type),
    status: graphNodeStatus(node.type),
    coverageStatus: relatedCoverage?.status ?? 'unknown',
    owners: relatedCoverage?.owners ?? [],
    sourceRef,
    officialLink: node.url ?? officialLinkForNode(node),
    confidenceSummary,
    trustLevel: 'canonical',
    provenance: canonicalProvenance(sourceRef, confidenceSummary),
    rawNode: node,
  };
}

function toGraphLink(edge: RouteEdge): GraphLink {
  const sourceRef = missingSourceRef(edge.source_ref);
  const confidence = edge.confidence ?? 'unknown';
  return {
    source: edge.source,
    target: edge.target,
    relationship: edge.relationship,
    label: graphRelationshipLabel(edge.relationship),
    confidence,
    sourceRef,
    sourceKind: edge.source_kind ?? 'unknown',
    trustLevel: 'canonical',
    provenance: canonicalProvenance(sourceRef, confidence, edge.source_kind),
    rawEdge: edge,
  };
}

function buildStats(nodes: GraphNode[], links: GraphLink[]): GraphStats {
  return {
    totalNodes: nodes.length,
    totalLinks: links.length,
    canonicalNodes: nodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend'].includes(node.type)).length,
    threatNodes: nodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'artifact'].includes(node.type)).length,
    defenseNodes: nodes.filter((node) => ['control', 'detection', 'evidence', 'gap', 'action'].includes(node.type)).length,
    gapNodes: nodes.filter((node) => node.type === 'gap').length,
    evidenceNodes: nodes.filter((node) => node.type === 'evidence').length,
    actionNodes: nodes.filter((node) => node.type === 'action').length,
  };
}

function buildWarnings(routeNodes: RouteNode[], routeEdges: RouteEdge[], nodes: GraphNode[], links: GraphLink[], scope: GraphScope): string[] {
  const warnings: string[] = [];
  const routeIds = new Set(routeNodes.map((node) => node.id));
  const invalidEdges = routeEdges.filter((edge) => !routeIds.has(edge.source) || !routeIds.has(edge.target));
  if (invalidEdges.length) warnings.push(`${invalidEdges.length} route edges reference nodes outside the supplied route node set.`);
  if (nodes.length === 0) warnings.push(`No visible nodes for scope '${scope}'.`);
  const visibleIds = new Set(nodes.map((node) => node.id));
  const invalidVisibleLinks = links.filter((link) => !visibleIds.has(link.source) || !visibleIds.has(link.target));
  if (invalidVisibleLinks.length) warnings.push(`${invalidVisibleLinks.length} visible links reference hidden nodes.`);
  return warnings;
}

function nodeSourceRef(node: RouteNode): string {
  return missingSourceRef(node.metadata?.source_ref ?? node.metadata?.mapping_file ?? node.metadata?.source);
}

function officialLinkForNode(node: RouteNode): string {
  if (node.type === 'cve') return `https://www.cve.org/CVERecord?id=${node.id}`;
  if (node.type === 'cwe') return `https://cwe.mitre.org/data/definitions/${node.id.replace('CWE-', '')}.html`;
  if (node.type === 'capec') return `https://capec.mitre.org/data/definitions/${node.id.replace('CAPEC-', '')}.html`;
  if (node.type === 'attack') return `https://attack.mitre.org/techniques/${node.id.replace('.', '/')}/`;
  if (node.type === 'd3fend') return `https://d3fend.mitre.org/technique/${node.id}/`;
  return '';
}

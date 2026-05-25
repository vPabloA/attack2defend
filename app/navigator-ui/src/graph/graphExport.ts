import type { GraphViewModel } from './graphModel';
import { CANONICAL_CHAIN_LABEL, CANONICAL_CHAIN } from './canonicalChain';

export function exportCanonicalChain(view: GraphViewModel) {
  return {
    capability: 'attack2defend.canonical_chain',
    principle: CANONICAL_CHAIN_LABEL,
    input: view.input,
    chain: Object.fromEntries(
      CANONICAL_CHAIN.map((type) => [type, view.canonicalChain[type].map((node) => ({ id: node.id, type: node.type, name: node.name, url: node.url ?? '' }))])
    ),
    missing_segments: view.missingSegments,
    source_refs: [...new Set(view.nodes.map((node) => node.sourceRef).filter((ref) => ref !== 'missing_source_ref'))].sort(),
    confidence_summary: summarizeLinkConfidence(view),
  };
}

export function exportVisibleGraph(view: GraphViewModel) {
  return {
    capability: 'attack2defend.visible_graph',
    principle: CANONICAL_CHAIN_LABEL,
    input: view.input,
    scope: view.visibleScope,
    nodes: view.nodes.map((node) => ({
      id: node.id,
      label: node.label,
      type: node.type,
      status: node.status,
      coverage_status: node.coverageStatus,
      owners: node.owners,
      source_ref: node.sourceRef,
      confidence_summary: node.confidenceSummary,
      trust_level: node.trustLevel,
      official_link: node.officialLink,
    })),
    links: view.links.map((link) => ({
      source: link.source,
      target: link.target,
      relationship: link.relationship,
      label: link.label,
      confidence: link.confidence,
      source_ref: link.sourceRef,
      source_kind: link.sourceKind,
      trust_level: link.trustLevel,
    })),
    stats: view.stats,
    warnings: view.warnings,
  };
}

export function exportMcpGraphPayload(view: GraphViewModel) {
  return {
    capability: 'attack2defend.graph_explore',
    principle: CANONICAL_CHAIN_LABEL,
    input: view.input,
    scope: view.visibleScope,
    threat_route: view.nodes.filter((node) => ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'artifact'].includes(node.type)).map(toMcpNode),
    defense_route: view.nodes.filter((node) => ['control', 'detection', 'evidence', 'gap', 'action'].includes(node.type)).map(toMcpNode),
    gaps: view.defenseExtension.gaps.map(toMcpNode),
    evidence_requirements: view.defenseExtension.evidence.map(toMcpNode),
    recommended_next_actions: view.defenseExtension.actions.map(toMcpNode),
    ai_assist_ready: true,
    source_refs: [...new Set(view.nodes.map((node) => node.sourceRef).concat(view.links.map((link) => link.sourceRef)).filter((ref) => ref !== 'missing_source_ref'))].sort(),
    confidence_summary: summarizeLinkConfidence(view),
    warnings: view.warnings,
  };
}

export function exportGapPaths(view: GraphViewModel) {
  const gapIds = new Set(view.defenseExtension.gaps.map((node) => node.id));
  return {
    capability: 'attack2defend.graph_gap_paths',
    principle: CANONICAL_CHAIN_LABEL,
    input: view.input,
    scope: view.visibleScope,
    gap_paths: view.links
      .filter((link) => gapIds.has(link.target) || gapIds.has(link.source))
      .map((link) => ({
        canonical_context: flattenCanonicalIds(view),
        defense_path: [link.source, link.target],
        relationship: link.relationship,
        blocking_reason: link.relationship === 'missing_evidence_creates_gap' ? 'missing evidence' : 'gap relationship requires validation',
        owner: findOwnerForNode(view, link.target) || findOwnerForNode(view, link.source) || 'SOC / Detection Engineering',
        source_ref: link.sourceRef,
      })),
  };
}

export function exportEvidenceRequirements(view: GraphViewModel) {
  return {
    capability: 'attack2defend.graph_evidence_requirements',
    principle: CANONICAL_CHAIN_LABEL,
    input: view.input,
    canonical_chain: flattenCanonicalIds(view),
    evidence: view.defenseExtension.evidence.map((node) => ({
      id: node.id,
      name: node.rawNode.name,
      related_detection: relatedNeighbor(view, node.id, 'detection'),
      related_attack: relatedNeighbor(view, node.id, 'attack'),
      related_d3fend: relatedNeighbor(view, node.id, 'd3fend'),
      source_ref: node.sourceRef,
      status: 'required',
    })),
  };
}

export function exportAiContextPacket(view: GraphViewModel) {
  return view.aiContextPacket;
}

function toMcpNode(node: GraphViewModel['nodes'][number]) {
  return {
    id: node.id,
    type: node.type,
    name: node.rawNode.name,
    status: node.status,
    coverage_status: node.coverageStatus,
    owners: node.owners,
    source_ref: node.sourceRef,
    confidence_summary: node.confidenceSummary,
  };
}

function summarizeLinkConfidence(view: GraphViewModel) {
  return view.links.reduce<Record<string, number>>((acc, link) => {
    acc[link.confidence] = (acc[link.confidence] ?? 0) + 1;
    return acc;
  }, {});
}

function flattenCanonicalIds(view: GraphViewModel): string[] {
  return CANONICAL_CHAIN.flatMap((type) => view.canonicalChain[type].map((node) => node.id));
}

function findOwnerForNode(view: GraphViewModel, nodeId: string): string {
  return view.nodes.find((node) => node.id === nodeId)?.owners[0] ?? '';
}

function relatedNeighbor(view: GraphViewModel, nodeId: string, type: string): string {
  const neighbors = view.links
    .filter((link) => link.source === nodeId || link.target === nodeId)
    .map((link) => (link.source === nodeId ? link.target : link.source));
  return view.nodes.find((node) => neighbors.includes(node.id) && node.type === type)?.id ?? '';
}

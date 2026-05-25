import type { RouteEdge, RouteNode } from '../types/attack2defend';
import type { GraphScope } from './graphFilters';
import type { CanonicalChain } from './canonicalChain';
import { CANONICAL_CHAIN_LABEL, canonicalMissingSegments, flattenCanonicalChain } from './canonicalChain';

export type AiAssistTask =
  | 'explain_visible_graph'
  | 'summarize_gaps'
  | 'suggest_validations'
  | 'draft_detection_ideas'
  | 'generate_executive_summary'
  | 'create_hunting_hypothesis';

export type AiContextPacket = {
  capability: 'attack2defend.ai_context_packet';
  principle: typeof CANONICAL_CHAIN_LABEL;
  task: AiAssistTask;
  input: string;
  visible_scope: GraphScope;
  bundle_full_context_sent: false;
  canonical_chain: Record<string, Array<Pick<RouteNode, 'id' | 'type' | 'name' | 'description' | 'url'>>>;
  visible_nodes: Array<Pick<RouteNode, 'id' | 'type' | 'name' | 'description' | 'url'>>;
  visible_edges: Array<Pick<RouteEdge, 'source' | 'target' | 'relationship' | 'confidence' | 'source_ref' | 'source_kind'>>;
  source_refs: string[];
  confidence_summary: Record<string, number>;
  missing_segments: string[];
  cost_control: {
    context_scope: 'visible_subgraph';
    cache_key_basis: string[];
  };
};

export function buildAiContextPacket(params: {
  task?: AiAssistTask;
  input: string;
  visibleScope: GraphScope;
  canonicalChain: CanonicalChain;
  visibleNodes: RouteNode[];
  visibleEdges: RouteEdge[];
  bundleVersion?: string;
}): AiContextPacket {
  const task = params.task ?? 'explain_visible_graph';
  const sourceRefs = collectSourceRefs(params.visibleNodes, params.visibleEdges);
  return {
    capability: 'attack2defend.ai_context_packet',
    principle: CANONICAL_CHAIN_LABEL,
    task,
    input: params.input,
    visible_scope: params.visibleScope,
    bundle_full_context_sent: false,
    canonical_chain: Object.fromEntries(
      Object.entries(params.canonicalChain).map(([type, nodes]) => [type, nodes.map(toCompactNode)])
    ),
    visible_nodes: params.visibleNodes.map(toCompactNode),
    visible_edges: params.visibleEdges.map(toCompactEdge),
    source_refs: sourceRefs,
    confidence_summary: summarizeConfidence(params.visibleEdges),
    missing_segments: canonicalMissingSegments(params.canonicalChain).map(String),
    cost_control: {
      context_scope: 'visible_subgraph',
      cache_key_basis: [params.input, params.visibleScope, params.bundleVersion ?? 'unknown_bundle_version', task],
    },
  };
}

function toCompactNode(node: RouteNode) {
  return {
    id: node.id,
    type: node.type,
    name: node.name,
    description: node.description,
    url: node.url,
  };
}

function toCompactEdge(edge: RouteEdge) {
  return {
    source: edge.source,
    target: edge.target,
    relationship: edge.relationship,
    confidence: edge.confidence,
    source_ref: edge.source_ref,
    source_kind: edge.source_kind,
  };
}

function collectSourceRefs(nodes: RouteNode[], edges: RouteEdge[]): string[] {
  const refs = new Set<string>();
  for (const node of [...nodes, ...flattenCanonicalChain({ cve: [], cwe: [], capec: [], attack: [], d3fend: [] })]) {
    const ref = node.metadata?.source_ref ?? node.metadata?.mapping_file ?? node.metadata?.source;
    if (typeof ref === 'string' && ref.trim()) refs.add(ref.trim());
  }
  for (const edge of edges) {
    if (edge.source_ref?.trim()) refs.add(edge.source_ref.trim());
  }
  return [...refs].sort();
}

function summarizeConfidence(edges: RouteEdge[]): Record<string, number> {
  return edges.reduce<Record<string, number>>((acc, edge) => {
    const key = edge.confidence ?? 'unknown';
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
}

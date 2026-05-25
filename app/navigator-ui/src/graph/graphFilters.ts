import type { NodeType, RouteEdge, RouteNode } from '../types/attack2defend';
import { CANONICAL_CHAIN, isCanonicalChainType } from './canonicalChain';

export type GraphScope =
  | 'canonical_chain'
  | 'threat_route'
  | 'defense_readiness'
  | 'gaps_only'
  | 'evidence_view'
  | 'owners_view'
  | 'full_traceability';

export type GraphFilters = {
  scope: GraphScope;
  nodeTypes?: NodeType[];
  includeArtifacts?: boolean;
  owner?: string;
  maxNodes?: number;
  maxLinks?: number;
};

const DEFENSE_TYPES: NodeType[] = ['control', 'detection', 'evidence', 'gap', 'action'];
const THREAT_TYPES: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'artifact'];

export function allowedTypesForScope(scope: GraphScope): NodeType[] {
  if (scope === 'canonical_chain') return [...CANONICAL_CHAIN];
  if (scope === 'threat_route') return THREAT_TYPES;
  if (scope === 'defense_readiness') return ['d3fend', ...DEFENSE_TYPES];
  if (scope === 'gaps_only') return ['attack', 'd3fend', 'detection', 'evidence', 'gap', 'action'];
  if (scope === 'evidence_view') return ['attack', 'd3fend', 'detection', 'evidence', 'gap'];
  if (scope === 'owners_view') return ['d3fend', ...DEFENSE_TYPES];
  return ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'artifact', ...DEFENSE_TYPES];
}

export function filterNodesByScope(nodes: RouteNode[], filters: GraphFilters): RouteNode[] {
  const allowed = new Set(filters.nodeTypes ?? allowedTypesForScope(filters.scope));
  const scoped = nodes.filter((node) => allowed.has(node.type));
  const withArtifacts = filters.includeArtifacts ? scoped : scoped.filter((node) => node.type !== 'artifact' || filters.scope === 'full_traceability');
  const limited = typeof filters.maxNodes === 'number' ? withArtifacts.slice(0, filters.maxNodes) : withArtifacts;
  return prioritizeCanonical(limited);
}

export function filterEdgesByVisibleNodes(edges: RouteEdge[], visibleNodeIds: Set<string>, maxLinks?: number): RouteEdge[] {
  const scoped = edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target));
  return typeof maxLinks === 'number' ? scoped.slice(0, maxLinks) : scoped;
}

function prioritizeCanonical(nodes: RouteNode[]): RouteNode[] {
  return [...nodes].sort((left, right) => {
    const leftCanonical = isCanonicalChainType(left.type);
    const rightCanonical = isCanonicalChainType(right.type);
    if (leftCanonical !== rightCanonical) return leftCanonical ? -1 : 1;
    if (leftCanonical && rightCanonical) return CANONICAL_CHAIN.indexOf(left.type) - CANONICAL_CHAIN.indexOf(right.type) || left.id.localeCompare(right.id);
    return left.type.localeCompare(right.type) || left.id.localeCompare(right.id);
  });
}

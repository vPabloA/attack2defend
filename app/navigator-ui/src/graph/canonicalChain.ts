import type { NodeType, RouteNode } from '../types/attack2defend';

export const CANONICAL_CHAIN: readonly NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend'] as const;

export const CANONICAL_CHAIN_LABEL = 'CVE → CWE → CAPEC → ATT&CK → D3FEND';

export type CanonicalChain = Record<(typeof CANONICAL_CHAIN)[number], RouteNode[]>;

export function emptyCanonicalChain(): CanonicalChain {
  return {
    cve: [],
    cwe: [],
    capec: [],
    attack: [],
    d3fend: [],
  };
}

export function canonicalStageIndex(type: NodeType): number {
  return CANONICAL_CHAIN.indexOf(type);
}

export function isCanonicalChainType(type: NodeType): type is (typeof CANONICAL_CHAIN)[number] {
  return CANONICAL_CHAIN.includes(type);
}

export function buildCanonicalChain(nodes: RouteNode[]): CanonicalChain {
  const chain = emptyCanonicalChain();
  for (const node of nodes) {
    if (isCanonicalChainType(node.type)) chain[node.type].push(node);
  }
  for (const type of CANONICAL_CHAIN) {
    chain[type] = [...chain[type]].sort((left, right) => left.id.localeCompare(right.id));
  }
  return chain;
}

export function flattenCanonicalChain(chain: CanonicalChain): RouteNode[] {
  return CANONICAL_CHAIN.flatMap((type) => chain[type]);
}

export function canonicalMissingSegments(chain: CanonicalChain): NodeType[] {
  return CANONICAL_CHAIN.filter((type) => chain[type].length === 0);
}

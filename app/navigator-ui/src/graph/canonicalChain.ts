import type { NodeType, RouteNode } from '../types/attack2defend';

export const CANONICAL_CHAIN = ['cve', 'cwe', 'capec', 'attack', 'd3fend'] as const;

export type CanonicalNodeType = (typeof CANONICAL_CHAIN)[number];

export const CANONICAL_CHAIN_LABEL = 'CVE → CWE → CAPEC → ATT&CK → D3FEND';

export type CanonicalChain = Record<CanonicalNodeType, RouteNode[]>;

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
  return CANONICAL_CHAIN.includes(type as CanonicalNodeType) ? CANONICAL_CHAIN.indexOf(type as CanonicalNodeType) : -1;
}

export function isCanonicalChainType(type: NodeType): type is CanonicalNodeType {
  return CANONICAL_CHAIN.includes(type as CanonicalNodeType);
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

export function canonicalMissingSegments(chain: CanonicalChain): CanonicalNodeType[] {
  return CANONICAL_CHAIN.filter((type) => chain[type].length === 0);
}

import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import { buildRouteViewModel, deriveConfidenceBadge } from './routeViewModel';

const nodes: RouteNode[] = [
  { id: 'CVE-2099-0001', type: 'cve', name: 'Fixture CVE', metadata: { source_ref: 'fixture:cve' } },
  { id: 'CWE-306', type: 'cwe', name: 'Missing Authentication', metadata: { source_ref: 'fixture:cwe' } },
  { id: 'CAPEC-115', type: 'capec', name: 'Authentication Bypass', metadata: { source_ref: 'fixture:capec' } },
  { id: 'T1190', type: 'attack', name: 'Exploit Public-Facing Application', metadata: { source_ref: 'fixture:attack' } },
  { id: 'D3-MFA', type: 'd3fend', name: 'Multi-factor Authentication', metadata: { source_ref: 'fixture:d3fend' } },
];

const edges: RouteEdge[] = [
  { source: 'CVE-2099-0001', target: 'CWE-306', relationship: 'has_weakness', confidence: 'high', source_ref: 'fixture:edge:cve-cwe' },
  { source: 'CWE-306', target: 'CAPEC-115', relationship: 'weakness_enables_attack_pattern', confidence: 'high', source_ref: 'fixture:edge:cwe-capec' },
  { source: 'CAPEC-115', target: 'T1190', relationship: 'attack_pattern_maps_to_technique', confidence: 'medium', source_ref: 'fixture:edge:capec-attack' },
  { source: 'T1190', target: 'D3-MFA', relationship: 'technique_mitigated_by_countermeasure', confidence: 'medium', source_ref: 'fixture:edge:attack-d3fend' },
];

const bundle: KnowledgeBundle = {
  metadata: { contract_version: 'fixture.v1', generated_at: '2099-01-01T00:00:00Z' },
  nodes,
  edges,
};

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

export function runRouteViewModelContractFixture(): void {
  assert(deriveConfidenceBadge({ sourceKind: 'MITRE' }) === 'official', 'official badge should map from official source');
  assert(deriveConfidenceBadge({ inferred: true }) === 'analytical_inferred', 'inferred badge should map to analytical_inferred');
  assert(deriveConfidenceBadge({ basis: 'baseline mapping' }) === 'baseline', 'baseline badge should map from baseline basis');
  assert(deriveConfidenceBadge({ status: 'conditional' }) === 'conditional', 'conditional badge should map from conditional status');
  assert(deriveConfidenceBadge({ relationship: 'post exploitation path' }) === 'unknown', 'unknown should remain fallback for weak signal');

  const model = buildRouteViewModel({
    bundle,
    query: 'CVE-2099-0001',
    selectedIds: ['CVE-2099-0001'],
    filters: { scope: 'canonical_chain' },
  });

  assert(model.found === true, 'model should resolve the selected route');
  assert(model.canonicalPath.length > 0, 'canonical path should exist for fixture');
  assert(model.nodes.length > 0, 'visible nodes should exist for fixture');
  assert(model.edges.length > 0, 'visible edges should exist for fixture');
  assert(model.tier1Readout.bullets.length > 0, 'tier1 readout should contain bullets');
  assert(model.coherence.length > 0, 'coherence panel should contain items');
}

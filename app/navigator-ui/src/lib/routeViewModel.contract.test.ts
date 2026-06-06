import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import { buildRouteViewModel, buildRouteViewModelFromPreview, deriveConfidenceBadge } from './routeViewModel';
import type { PreviewRouteArtifact } from './routeViewModel';

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

const minimalPreviewArtifact: PreviewRouteArtifact = {
  artifact_type: 'attack2defend.preview_route',
  canonical: false,
  input: 'CVE-2026-4342',
  normalized_input: 'CVE-2026-4342',
  generated_at: '2099-01-01T00:00:00Z',
  source: 'mock',
  nodes: [
    { id: 'CVE-2026-4342', type: 'cve', name: 'CVE-2026-4342 (preview)' },
    { id: 'CWE-20', type: 'cwe', name: 'Improper Input Validation (inferred)' },
    { id: 'T1059', type: 'attack', name: 'Command Interpreter (conditional)' },
    { id: 'D3-IPFIX', type: 'd3fend', name: 'Network Traffic Filtering (suggested)' },
  ],
  edges: [
    { source: 'CVE-2026-4342', target: 'CWE-20', relationship: 'has_weakness', confidence: 'low' },
    { source: 'CWE-20', target: 'T1059', relationship: 'attack_pattern_maps_to_technique', confidence: 'low' },
    { source: 'T1059', target: 'D3-IPFIX', relationship: 'technique_mitigated_by_countermeasure', confidence: 'low' },
  ],
  warnings: ['Preview only — not in canonical local bundle.'],
  provenance: [
    { id: 'CVE-2026-4342', source: 'on-demand-resolution', trust: 'unknown' },
    { id: 'CWE-20', source: 'on-demand-resolution', trust: 'inferred' },
    { id: 'T1059', source: 'on-demand-resolution', trust: 'inferred' },
    { id: 'D3-IPFIX', source: 'on-demand-resolution', trust: 'mock' },
  ],
};

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

export function runRouteViewModelContractFixture(): void {
  // Badge derivation contract
  assert(deriveConfidenceBadge({ sourceKind: 'MITRE' }) === 'official', 'official badge should map from official source');
  assert(deriveConfidenceBadge({ inferred: true }) === 'analytical_inferred', 'inferred badge should map to analytical_inferred');
  assert(deriveConfidenceBadge({ basis: 'baseline mapping' }) === 'baseline', 'baseline badge should map from baseline basis');
  assert(deriveConfidenceBadge({ status: 'conditional' }) === 'conditional', 'conditional badge should map from conditional status');
  assert(deriveConfidenceBadge({ relationship: 'post exploitation path' }) === 'unknown', 'unknown should remain fallback for weak signal');

  // Bundle route resolution
  const model = buildRouteViewModel({
    bundle,
    query: 'CVE-2099-0001',
    selectedIds: ['CVE-2099-0001'],
    filters: { scope: 'canonical_chain' },
  });

  assert(model.found === true, 'model should resolve the selected route');
  assert(model.isPreview === false, 'bundle model should not be preview');
  assert(model.sourceMode === 'bundle', 'bundle model sourceMode should be bundle');
  assert(model.canonicalPath.length > 0, 'canonical path should exist for fixture');
  assert(model.nodes.length > 0, 'visible nodes should exist for fixture');
  assert(model.edges.length > 0, 'visible edges should exist for fixture');
  assert(model.tier1Readout.bullets.length > 0, 'tier1 readout should contain bullets');
  assert(model.coherence.length > 0, 'coherence panel should contain items');

  // Not-found case
  const notFound = buildRouteViewModel({
    bundle,
    query: 'CVE-2026-9999',
    selectedIds: [],
  });
  assert(notFound.found === false, 'unknown CVE should not be found');
  assert(notFound.isPreview === false, 'not-found bundle model should not be preview');

  // Preview artifact to RouteViewModel
  const preview = buildRouteViewModelFromPreview(minimalPreviewArtifact);
  assert(preview.found === true, 'preview model should report found=true');
  assert(preview.isPreview === true, 'preview model should be marked as preview');
  assert(preview.sourceMode === 'preview', 'preview model sourceMode should be preview');
  assert(preview.nodes.length > 0, 'preview model should have nodes');
  assert(preview.edges.length > 0, 'preview model should have edges');
  assert(preview.warnings.some((w) => w.includes('Preview')), 'preview model should have preview warning');
  assert(preview.tier1Readout.confidence === 'preview', 'preview readout confidence should be preview');
  assert(preview.canonicalPath.length > 0, 'preview canonical path should include CVE layer nodes');
}

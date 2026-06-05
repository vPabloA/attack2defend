import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import { buildGraphViewModel } from './graphModel';
import { exportAiContextPacket, exportCanonicalChain, exportEvidenceRequirements, exportGapPaths, exportMcpGraphPayload, exportVisibleGraph } from './graphExport';

const nodes: RouteNode[] = [
  { id: 'CVE-2099-0001', type: 'cve', name: 'Fixture CVE', metadata: { source_ref: 'fixture:cve' } },
  { id: 'CWE-306', type: 'cwe', name: 'Missing Authentication', metadata: { source_ref: 'fixture:cwe' } },
  { id: 'CAPEC-115', type: 'capec', name: 'Authentication Bypass', metadata: { source_ref: 'fixture:capec' } },
  { id: 'T1190', type: 'attack', name: 'Exploit Public-Facing Application', metadata: { source_ref: 'fixture:attack' } },
  { id: 'D3-MFA', type: 'd3fend', name: 'Multi-factor Authentication', metadata: { source_ref: 'fixture:d3fend' } },
  { id: 'CTRL-MFA-001', type: 'control', name: 'Enforce MFA', metadata: { source_ref: 'fixture:control' } },
  { id: 'DET-AUTH-001', type: 'detection', name: 'Authentication anomaly detection', metadata: { source_ref: 'fixture:detection' } },
  { id: 'EV-AUTH-001', type: 'evidence', name: 'Authentication logs', metadata: { source_ref: 'fixture:evidence' } },
  { id: 'GAP-AUTH-001', type: 'gap', name: 'Missing auth telemetry', metadata: { source_ref: 'fixture:gap' } },
  { id: 'ACTION-AUTH-001', type: 'action', name: 'Enable auth telemetry', metadata: { source_ref: 'fixture:action' } },
];

const edges: RouteEdge[] = [
  { source: 'CVE-2099-0001', target: 'CWE-306', relationship: 'has_weakness', confidence: 'fixture_high', source_ref: 'fixture:edge:cve-cwe' },
  { source: 'CWE-306', target: 'CAPEC-115', relationship: 'weakness_enables_attack_pattern', confidence: 'fixture_high', source_ref: 'fixture:edge:cwe-capec' },
  { source: 'CAPEC-115', target: 'T1190', relationship: 'attack_pattern_maps_to_technique', confidence: 'fixture_medium', source_ref: 'fixture:edge:capec-attack' },
  { source: 'T1190', target: 'D3-MFA', relationship: 'technique_mitigated_by_countermeasure', confidence: 'fixture_medium', source_ref: 'fixture:edge:attack-d3fend' },
  { source: 'D3-MFA', target: 'CTRL-MFA-001', relationship: 'implemented_by', confidence: 'fixture_medium', source_ref: 'fixture:edge:d3fend-control' },
  { source: 'CTRL-MFA-001', target: 'DET-AUTH-001', relationship: 'validated_by_detection', confidence: 'fixture_medium', source_ref: 'fixture:edge:control-detection' },
  { source: 'DET-AUTH-001', target: 'EV-AUTH-001', relationship: 'requires_evidence', confidence: 'fixture_medium', source_ref: 'fixture:edge:detection-evidence' },
  { source: 'EV-AUTH-001', target: 'GAP-AUTH-001', relationship: 'missing_evidence_creates_gap', confidence: 'fixture_high', source_ref: 'fixture:edge:evidence-gap' },
  { source: 'GAP-AUTH-001', target: 'ACTION-AUTH-001', relationship: 'closed_by_action', confidence: 'fixture_high', source_ref: 'fixture:edge:gap-action' },
];

const bundle: KnowledgeBundle = {
  metadata: { contract_version: 'fixture.v1', generated_at: '2099-01-01T00:00:00Z' },
  nodes,
  edges,
  coverage: {
    'DET-AUTH-001': { status: 'partial', owners: ['Detection Engineering'] },
    'EV-AUTH-001': { status: 'missing', owners: ['SOC'] },
    'GAP-AUTH-001': { status: 'missing', owners: ['SOC'] },
    'ACTION-AUTH-001': { status: 'unknown', owners: ['Infra'] },
  },
};

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

export function runGraphModelContractFixture(): void {
  const view = buildGraphViewModel({
    bundle,
    routeNodes: nodes,
    routeEdges: edges,
    input: 'CVE-2099-0001',
    filters: { scope: 'defense_readiness' },
    aiTask: 'summarize_gaps',
  });

  assert(view.principle === 'CVE → CWE → CAPEC → ATT&CK → D3FEND', 'canonical principle must be preserved');
  assert(view.canonicalChain.cve[0]?.id === 'CVE-2099-0001', 'CVE stage must be preserved');
  assert(view.canonicalChain.cwe[0]?.id === 'CWE-306', 'CWE stage must be preserved');
  assert(view.canonicalChain.capec[0]?.id === 'CAPEC-115', 'CAPEC stage must be preserved');
  assert(view.canonicalChain.attack[0]?.id === 'T1190', 'ATT&CK stage must be preserved');
  assert(view.canonicalChain.d3fend[0]?.id === 'D3-MFA', 'D3FEND stage must be preserved');
  assert(view.links.every((link) => view.nodes.some((node) => node.id === link.source) && view.nodes.some((node) => node.id === link.target)), 'visible links must reference visible nodes');
  assert(view.links.every((link) => link.sourceRef !== 'missing_source_ref'), 'source_ref must be preserved for links');
  assert(view.nodes.every((node) => node.trustLevel === 'canonical'), 'graph nodes must remain canonical in core model');
  assert(view.aiContextPacket.bundle_full_context_sent === false, 'AI context packet must not send full bundle');

  const canonicalExport = exportCanonicalChain(view);
  const visibleExport = exportVisibleGraph(view);
  const mcpExport = exportMcpGraphPayload(view);
  const gapExport = exportGapPaths(view);
  const evidenceExport = exportEvidenceRequirements(view);
  const aiExport = exportAiContextPacket(view);

  assert(canonicalExport.capability === 'attack2defend.canonical_chain', 'canonical export capability mismatch');
  assert(visibleExport.capability === 'attack2defend.visible_graph', 'visible export capability mismatch');
  assert(mcpExport.capability === 'attack2defend.graph_explore', 'mcp export capability mismatch');
  assert(gapExport.capability === 'attack2defend.graph_gap_paths', 'gap export capability mismatch');
  assert(evidenceExport.capability === 'attack2defend.graph_evidence_requirements', 'evidence export capability mismatch');
  assert(aiExport.capability === 'attack2defend.ai_context_packet', 'ai context export capability mismatch');
}

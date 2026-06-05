import type { NodeType } from '../types/attack2defend';
import { canonicalStageIndex, isCanonicalChainType } from './canonicalChain';

export type GraphNodeStatus = 'canonical' | 'defense' | 'gap' | 'evidence' | 'action' | 'transit' | 'unknown';

export const NODE_TYPE_LABELS: Record<NodeType, string> = {
  cve: 'CVE',
  cwe: 'CWE',
  capec: 'CAPEC',
  attack: 'ATT&CK',
  d3fend: 'D3FEND',
  artifact: 'Artifact',
  control: 'Control',
  detection: 'Detection',
  evidence: 'Evidence',
  gap: 'Gap',
  action: 'Action',
};

export const RELATIONSHIP_LABELS: Record<string, string> = {
  has_weakness: 'has weakness',
  has_related_weakness: 'related weakness',
  vulnerability_has_weakness: 'has weakness',
  may_enable_attack_pattern: 'may enable',
  weakness_enables_attack_pattern: 'may enable',
  may_map_to_attack_technique: 'maps to',
  attack_pattern_maps_to_technique: 'maps to',
  may_lead_to_post_exploitation: 'may lead to',
  affects_artifact: 'affects',
  affects_or_requires_artifact: 'requires artifact',
  affects_product_or_platform: 'affects product',
  abuses_artifact: 'abuses',
  targets_artifact: 'targets',
  protects_artifact: 'protects',
  may_be_defended_by: 'defended by',
  may_be_detected_by: 'detected by',
  implemented_by: 'implemented by',
  protected_by_control: 'implemented by control',
  enables_detection: 'enables',
  validated_by_detection: 'validated by',
  requires_evidence: 'requires',
  missing_evidence_creates_gap: 'creates gap',
  closed_by_action: 'closed by',
  technique_mitigated_by_countermeasure: 'mitigated by',
};

export function graphNodeStatus(type: NodeType): GraphNodeStatus {
  if (isCanonicalChainType(type)) return 'canonical';
  if (type === 'gap') return 'gap';
  if (type === 'evidence') return 'evidence';
  if (type === 'action') return 'action';
  if (type === 'artifact') return 'transit';
  if (['control', 'detection'].includes(type)) return 'defense';
  return 'unknown';
}

export function graphNodeWeight(type: NodeType): number {
  if (type === 'cve') return 10;
  if (type === 'attack') return 9;
  if (type === 'd3fend') return 8;
  if (type === 'gap') return 8;
  if (type === 'detection') return 7;
  if (type === 'evidence') return 6;
  if (isCanonicalChainType(type)) return 6 + Math.max(0, canonicalStageIndex(type));
  return 4;
}

export function graphNodeLabel(id: string, name: string): string {
  return name && name !== id ? `${id} · ${name}` : id;
}

export function graphRelationshipLabel(relationship: string): string {
  return RELATIONSHIP_LABELS[relationship] ?? relationship;
}

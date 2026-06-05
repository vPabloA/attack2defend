export type SourceType =
  | 'canonical_bundle'
  | 'deterministic_resolver'
  | 'ai_assisted_candidate'
  | 'external_enrichment'
  | 'analyst_candidate'
  | 'runtime_assist';

export type TrustLevel =
  | 'canonical'
  | 'validated_candidate'
  | 'candidate'
  | 'context';

export type ProvenanceRecord = {
  source_type: SourceType;
  trust_level: TrustLevel;
  source_ref: string;
  confidence?: string;
  source_kind?: string;
  generated_at?: string;
  provider?: string;
  model?: string;
  confidence_basis?: string;
};

export const CANONICAL_PROVENANCE: Pick<ProvenanceRecord, 'source_type' | 'trust_level'> = {
  source_type: 'canonical_bundle',
  trust_level: 'canonical',
};

export function missingSourceRef(value: unknown): string {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : 'missing_source_ref';
}

export function canonicalProvenance(sourceRef: unknown, confidence?: string, sourceKind?: string): ProvenanceRecord {
  return {
    ...CANONICAL_PROVENANCE,
    source_ref: missingSourceRef(sourceRef),
    confidence,
    source_kind: sourceKind,
  };
}

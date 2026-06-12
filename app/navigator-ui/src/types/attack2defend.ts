export type NodeType =
  | 'cve'
  | 'cwe'
  | 'capec'
  | 'attack'
  | 'd3fend'
  | 'artifact'
  | 'control'
  | 'detection'
  | 'evidence'
  | 'gap'
  | 'action';

export type CoverageStatus = 'covered' | 'partial' | 'missing' | 'unknown' | 'not_applicable';
export type ReviewStatus = 'approved' | 'candidate' | 'pending' | 'rejected';
export type SearchMode = 'empty' | 'direct' | 'reverse' | 'batch' | 'mixed';
export type ReviewFilter = 'all' | 'canonical' | 'ai_inferred' | 'pending';

export type SearchContext = {
  normalized_query: string;
  tokens: string[];
  mode: SearchMode;
  primary_id?: string | null;
  reverse_anchor?: string | null;
  associated_cves: string[];
  selected_ids: string[];
  message?: string;
};

export type BundleStats = {
  total_cves_processed?: number;
  total_nodes?: number;
  total_edges?: number;
  total_canonical_chains?: number;
  cves_with_complete_route?: number;
  cves_without_route?: number;
  cves_with_candidate_route?: number;
  review_queue_size?: number;
  smoke_test_hits?: number;
  smoke_test_warnings?: number;
  bundle_bytes?: number;
  source_years?: number[];
};

export type ReverseIndex = {
  by_cwe?: Record<string, string[]>;
  by_capec?: Record<string, string[]>;
  by_attack?: Record<string, string[]>;
  by_d3fend?: Record<string, string[]>;
};

export type D3fendControl = {
  id: string;
  name: string;
  justification: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
};

export type SocTechnique = {
  id: string;
  name: string;
  justification?: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
};

export type SocCandidate = {
  id: string;
  label: string;
  text: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
};

export type SocActionPack = {
  attack_techniques: SocTechnique[];
  d3fend_controls: D3fendControl[];
  compensating_controls: SocCandidate[];
  detection_rules: SocCandidate[];
  evidence_to_review: SocCandidate[];
  ioc_candidates: SocCandidate[];
  gaps: SocCandidate[];
  risk_acceptance_matrix: Array<{
    id: string;
    label: string;
    minimum_controls: string[];
    rationale: string;
    provenance?: string;
    confidence?: string;
    review_status?: ReviewStatus;
  }>;
};

export type CveChainLink = {
  cve?: string;
  cwe?: string;
  capec?: string;
  attack?: string;
  d3fend?: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
};

export type Tier1Readout = {
  title: string;
  bullets: string[];
  summary?: string;
  severity?: string;
  cvss?: string | number | Record<string, unknown> | null;
  vector?: string;
  confidence?: string;
  provenance?: string;
  review_status?: ReviewStatus;
  mode?: 'cve' | 'node' | 'fallback';
  associated_cves?: string[];
  attack_techniques?: SocTechnique[];
  d3fend_controls?: D3fendControl[];
  compensating_controls?: SocCandidate[];
  detection_guidance?: SocCandidate[];
  evidence_to_review?: SocCandidate[];
  gaps?: SocCandidate[];
  risk_acceptance_matrix?: SocActionPack['risk_acceptance_matrix'];
  copy_paste_10_lines?: string[];
  checklist?: string[];
  escalation_criteria?: string[];
  source_ref?: string;
  soc_action_pack?: SocActionPack;
};

export type CveRecord = {
  id: string;
  type: 'cve';
  label: string;
  description?: string;
  severity?: string | null;
  cvss?: string | number | Record<string, unknown> | null;
  published?: string | null;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
  canonical_chain: CveChainLink[];
  soc_action_pack: SocActionPack;
  tier1_readout: Tier1Readout;
  source_year?: number;
  route_count?: number;
  vendor?: string | null;
  product?: string | null;
  kev?: boolean;
};

export type ReviewQueueItem = {
  id: string;
  label: string;
  review_status: ReviewStatus;
  provenance?: string;
  confidence?: string;
  reason?: string;
  cve_count?: number;
  route_count?: number;
  selected?: boolean;
  focus?: string;
};

export type BundleSummary = {
  bundle_version?: string;
  generated_at?: string;
  source?: string;
  provenance?: string;
  node_count: number;
  edge_count: number;
  cve_count: number;
  route_count: number;
  review_queue_count: number;
  last_sync?: string;
  stats?: BundleStats;
};

export type RouteNode = {
  id: string;
  type: NodeType;
  name: string;
  description?: string;
  url?: string;
  metadata?: Record<string, unknown>;
};

export type RouteEdge = {
  source: string;
  target: string;
  relationship: string;
  confidence?: string;
  source_ref?: string;
  source_kind?: string;
  owner?: string;
  priority?: string;
};

export type CoverageRecord = {
  status?: CoverageStatus;
  controls?: string[];
  detections?: string[];
  evidence?: string[];
  gaps?: string[];
  owners?: string[];
};

export type RouteMetadata = {
  id: string;
  input: string;
  name: string;
  curation_status?: string;
  notes?: string;
  file?: string;
};

export type KnowledgeBundle = {
  bundle_version?: string;
  generated_at?: string;
  source?: string;
  provenance?: string;
  metadata: {
    contract_version?: string;
    builder_version?: string;
    generated_at?: string;
    mode?: string;
    counts?: Record<string, number>;
    warnings?: unknown[];
    public_sources?: unknown[];
    public_source_failures?: unknown[];
    seed_inputs?: { required?: string[]; available?: string[] };
  };
  nodes: RouteNode[];
  edges: RouteEdge[];
  canonical_chain?: CveChainLink[];
  cves?: Record<string, CveRecord>;
  reverse_index?: ReverseIndex;
  review_queue?: ReviewQueueItem[];
  stats?: BundleStats;
  indexes?: {
    by_type?: Partial<Record<NodeType, string[]>>;
    outgoing?: Record<string, Array<{ target: string; relationship: string }>>;
    incoming?: Record<string, Array<{ source: string; relationship: string }>>;
    route_inputs?: string[];
    search?: Array<{ id: string; type: string; name: string; text: string }>;
    cpe_to_cve?: Record<string, string[]>;
    kev?: Record<string, Record<string, unknown>>;
    forward?: Record<string, Record<string, string[]>>;
    reverse?: Record<string, Record<string, string[]>>;
  };
  coverage?: Record<string, CoverageRecord>;
  routes?: RouteMetadata[];
  semantic_routes?: unknown[];
};

export type ResolvedRoute = {
  root: string;
  nodes: string[];
  edges: RouteEdge[];
};

export type CapabilityBridge = {
  source: string;
  target: string;
  relationship: string;
  confidence: string;
  source_ref: string;
};

export type CapabilityNode = RouteNode & {
  sourceRef: string;
  officialLink: string;
};

export type CapabilitySection = {
  type: NodeType;
  label: string;
  nodes: CapabilityNode[];
  emptyMessage: string;
};

export type RecommendedAction = {
  id: string;
  type: 'action';
  description_es: string;
  owner_guidance_es: string;
  source_ref: string;
  related_gap_id: string;
};

export type CapabilityView = {
  capability: 'attack2defend.resolve_defense_route';
  input: string;
  normalized_input: string;
  input_type: NodeType | 'unknown';
  coverage_status: string;
  confidence: string;
  executive_summary_es: string;
  decision_context_es: string;
  risk_rationale_es: string;
  consultative_conclusion_es: string[];
  threatStatus: string;
  defenseStatus: string;
  priority: {
    threat_relevance: string;
    exposure: string;
    defense_gap: string;
    final_priority: string;
    rationale: string;
    rationale_es: string;
  };
  threatSections: CapabilitySection[];
  defenseSections: CapabilitySection[];
  bridges: CapabilityBridge[];
  recommended_actions: RecommendedAction[];
  recommended_validations: Array<{ owner: string; text: string; evidence_expected?: string[]; source_ids?: string[] }>;
  suggested_detections: string[];
  node_reason_by_id: Record<string, string>;
  owners: string[];
  source_refs: string[];
  official_links: Array<{ node_id: string; node_type: string; url: string; source: string }>;
  gap_explanation_es: string;
  exportPayload: Record<string, unknown>;
};

export type CuratedRoute = {
  stages: Array<{ type: NodeType; label: string; nodes: CapabilityNode[] }>;
  counts: Partial<Record<NodeType, number>>;
  isPending: boolean;
};

export const THREAT_CHAIN_TYPES: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend'];
export const DEFENSE_EXTENSION_TYPES: NodeType[] = ['control', 'detection', 'evidence', 'gap', 'action'];
export const TRANSIT_TYPES: NodeType[] = ['artifact'];

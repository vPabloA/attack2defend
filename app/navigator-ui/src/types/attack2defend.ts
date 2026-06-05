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

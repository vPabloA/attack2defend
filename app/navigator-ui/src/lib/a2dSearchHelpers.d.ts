import type { KnowledgeBundle } from '../types/attack2defend';

export type SearchHit = {
  token: string;
  type: string;
  matches: string[];
};

export type SearchSelection = {
  normalizedQuery: string;
  tokens: string[];
  selectedIds: string[];
  associatedCves: string[];
  mode: 'empty' | 'direct' | 'reverse' | 'batch' | 'mixed';
  primaryId: string | null;
  reverseAnchor: string | null;
  message: string;
  hits: SearchHit[];
};

export type SearchSelectionOptions = {
  maxRoots?: number;
  maxReverseMatches?: number;
};

export declare function extractSearchTokens(raw: string): string[];
export declare function buildReverseIndex(bundle: KnowledgeBundle): {
  by_cwe: Record<string, string[]>;
  by_capec: Record<string, string[]>;
  by_attack: Record<string, string[]>;
  by_d3fend: Record<string, string[]>;
};
export declare function buildSearchIndex(bundle: KnowledgeBundle): {
  nodeMap: Map<string, { id: string; type: string; name: string }>;
  reverseIndex: ReturnType<typeof buildReverseIndex>;
};
export declare function resolveSearchSelection(bundle: KnowledgeBundle, rawQuery: string, options?: SearchSelectionOptions): SearchSelection;

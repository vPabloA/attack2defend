import type { ReviewStatus } from '../types/attack2defend';
import type { Tier1Readout } from './routeViewModel.ts';

export type ReadoutBucket = 'canonical' | 'candidate' | 'inferred' | 'fallback';

export type ReadoutSignal = {
  id: string;
  label: string;
  text: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
  bucket: ReadoutBucket;
};

export type ReadoutTopSection = {
  key: 'detections' | 'evidence' | 'gaps' | 'actions';
  title: string;
  items: ReadoutSignal[];
  hiddenCount: number;
  emptyText: string;
};

export type Tier1ReadoutPresentation = {
  summary: string;
  metadata: Array<{ label: string; value: string }>;
  bucketCounts: Record<ReadoutBucket, number>;
  visibleSectionKeys: Array<'summary' | 'metadata' | 'detections' | 'evidence' | 'gaps' | 'actions'>;
  collapsedSectionKeys: Array<'lineage' | 'supporting' | 'copy'>;
  topSections: ReadoutTopSection[];
  lineage: Record<ReadoutBucket, ReadoutSignal[]>;
  supporting: {
    attackTechniques: ReadoutSignal[];
    d3fendControls: ReadoutSignal[];
    compensatingControls: ReadoutSignal[];
    riskAcceptance: ReadoutSignal[];
    bullets: string[];
    copyPasteLines: string[];
    checklist: ReadoutSignal[];
    escalationCriteria: ReadoutSignal[];
    associatedCves: string[];
  };
  hasFallback: boolean;
};

export const TIER1_TOP_SECTION_LIMIT = 3;

export function buildTier1ReadoutPresentation(readout: Tier1Readout): Tier1ReadoutPresentation {
  const hasFallback = readout.mode === 'fallback';
  const summary = readout.summary ?? readout.title;
  const attackTechniques = normalizeTechniqueSignals(readout.attack_techniques ?? [], readout.mode);
  const d3fendControls = normalizeD3fendSignals(readout.d3fend_controls ?? [], readout.mode);
  const compensatingControls = normalizeCandidateSignals(readout.compensating_controls ?? [], readout.mode, 'Compensating control');
  const detectionGuidance = normalizeCandidateSignals(readout.detection_guidance ?? [], readout.mode, 'Detection guidance');
  const evidenceToReview = normalizeCandidateSignals(readout.evidence_to_review ?? [], readout.mode, 'Evidence');
  const gaps = normalizeCandidateSignals(readout.gaps ?? [], readout.mode, 'Gap');
  const riskAcceptance = normalizeRiskSignals(readout.risk_acceptance_matrix ?? [], readout.mode);
  const checklist = normalizeStringSignals(readout.checklist ?? [], readout.mode, 'Action');
  const escalationCriteria = normalizeStringSignals(readout.escalation_criteria ?? [], readout.mode, 'Escalation');
  const lineageSignals = [
    ...attackTechniques,
    ...d3fendControls,
    ...compensatingControls,
    ...detectionGuidance,
    ...evidenceToReview,
    ...gaps,
    ...riskAcceptance,
  ];
  const lineage = groupByBucket(lineageSignals);
  const bucketCounts = bucketCountsFromLineage(lineage);
  const metadata = buildMetadata(readout, bucketCounts);
  const topSections: ReadoutTopSection[] = [
    buildTopSection('detections', 'Top detections', detectionGuidance, 'No canonical or candidate detections available.'),
    buildTopSection('evidence', 'Top evidence', evidenceToReview, 'No canonical or candidate evidence available.'),
    buildTopSection('gaps', 'Top gaps', gaps, 'No canonical or candidate gaps available.'),
    buildTopSection('actions', 'Top actions', checklist, 'No canonical or candidate actions available.'),
  ];

  return {
    summary,
    metadata,
    bucketCounts,
    visibleSectionKeys: ['summary', 'metadata', 'detections', 'evidence', 'gaps', 'actions'],
    collapsedSectionKeys: ['lineage', 'supporting', 'copy'],
    topSections,
    lineage,
    supporting: {
      attackTechniques,
      d3fendControls,
      compensatingControls,
      riskAcceptance,
      bullets: readout.bullets ?? [],
      copyPasteLines: readout.copy_paste_10_lines ?? [],
      checklist,
      escalationCriteria,
      associatedCves: readout.associated_cves ?? [],
    },
    hasFallback,
  };
}

function buildMetadata(readout: Tier1Readout, bucketCounts: Record<ReadoutBucket, number>) {
  return [
    { label: 'Severity', value: String(readout.severity ?? 'No disponible en bundle local') },
    { label: 'CVSS', value: formatValue(readout.cvss) ?? 'No disponible en bundle local' },
    { label: 'Vector', value: String(readout.vector ?? 'No disponible en bundle local') },
    { label: 'Confidence', value: String(readout.confidence ?? 'Requiere validacion') },
    { label: 'Provenance', value: String(readout.provenance ?? 'unknown') },
    { label: 'Review', value: String(readout.review_status ?? 'candidate') },
    { label: 'Canonical', value: String(bucketCounts.canonical) },
    { label: 'Candidate', value: String(bucketCounts.candidate) },
    { label: 'Inferred', value: String(bucketCounts.inferred) },
    { label: 'Fallback', value: String(bucketCounts.fallback) },
  ];
}

function buildTopSection(
  key: ReadoutTopSection['key'],
  title: string,
  items: ReadoutSignal[],
  emptyText: string,
): ReadoutTopSection {
  const visibleItems = items.filter((item) => item.bucket === 'canonical' || item.bucket === 'candidate').slice(0, TIER1_TOP_SECTION_LIMIT);
  const hiddenCount = Math.max(0, items.filter((item) => item.bucket === 'canonical' || item.bucket === 'candidate').length - visibleItems.length);
  return {
    key,
    title,
    items: visibleItems,
    hiddenCount,
    emptyText,
  };
}

function normalizeTechniqueSignals(
  items: Array<{ id: string; name: string; justification?: string; provenance?: string; confidence?: string; review_status?: ReviewStatus }>,
  mode: Tier1Readout['mode'],
): ReadoutSignal[] {
  return items.map((item) => normalizeSignal({
    id: item.id,
    label: 'Technique',
    text: `${item.id} · ${item.name}${item.justification ? ` — ${item.justification}` : ''}`,
    provenance: item.provenance,
    confidence: item.confidence,
    review_status: item.review_status,
    mode,
  }));
}

function normalizeD3fendSignals(
  items: Array<{ id: string; name: string; justification: string; provenance?: string; confidence?: string; review_status?: ReviewStatus }>,
  mode: Tier1Readout['mode'],
): ReadoutSignal[] {
  return items.map((item) => normalizeSignal({
    id: item.id,
    label: 'D3FEND control',
    text: `${item.id} · ${item.name} — ${item.justification}`,
    provenance: item.provenance,
    confidence: item.confidence,
    review_status: item.review_status,
    mode,
  }));
}

function normalizeCandidateSignals(
  items: Array<{ id: string; label: string; text: string; provenance?: string; confidence?: string; review_status?: ReviewStatus }>,
  mode: Tier1Readout['mode'],
  label: string,
): ReadoutSignal[] {
  return items.map((item) => normalizeSignal({
    id: item.id,
    label,
    text: `${item.label || item.id}: ${item.text}`,
    provenance: item.provenance,
    confidence: item.confidence,
    review_status: item.review_status,
    mode,
  }));
}

function normalizeRiskSignals(
  items: Array<{ id: string; label: string; minimum_controls: string[]; rationale: string; provenance?: string; confidence?: string; review_status?: ReviewStatus }>,
  mode: Tier1Readout['mode'],
): ReadoutSignal[] {
  return items.map((item) => normalizeSignal({
    id: item.id,
    label: 'Risk acceptance',
    text: `${item.label}: ${item.minimum_controls.join(', ')} — ${item.rationale}`,
    provenance: item.provenance,
    confidence: item.confidence,
    review_status: item.review_status,
    mode,
  }));
}

function normalizeStringSignals(values: string[], mode: Tier1Readout['mode'], label: string): ReadoutSignal[] {
  return uniqueStrings(values).map((text, index) => normalizeSignal({
    id: `${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${index + 1}`,
    label,
    text,
    review_status: 'candidate',
    mode,
  }));
}

function normalizeSignal(input: {
  id: string;
  label: string;
  text: string;
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
  mode?: Tier1Readout['mode'];
}): ReadoutSignal {
  return {
    id: input.id,
    label: input.label,
    text: input.text,
    provenance: input.provenance,
    confidence: input.confidence,
    review_status: input.review_status,
    bucket: classifyReadoutBucket(input),
  };
}

export function classifyReadoutBucket(input: {
  provenance?: string;
  confidence?: string;
  review_status?: ReviewStatus;
  mode?: Tier1Readout['mode'];
}): ReadoutBucket {
  const provenance = String(input.provenance ?? '').trim().toLowerCase();
  const confidence = String(input.confidence ?? '').trim().toLowerCase();
  const reviewStatus = String(input.review_status ?? '').trim().toLowerCase();
  const mode = input.mode ?? 'node';

  if (provenance === 'fallback') return 'fallback';
  if (!provenance && mode === 'fallback' && !reviewStatus) return 'fallback';
  if (provenance.includes('canonical') || provenance.includes('official') || reviewStatus === 'approved') return 'canonical';
  if (provenance.includes('inferred')) return 'inferred';
  if (provenance.includes('derived') || provenance.includes('curated') || reviewStatus === 'candidate' || reviewStatus === 'pending') return 'candidate';
  if (confidence === 'low') return mode === 'fallback' ? 'fallback' : 'inferred';
  if (confidence === 'medium') return 'candidate';
  return mode === 'fallback' ? 'candidate' : 'candidate';
}

function groupByBucket(items: ReadoutSignal[]): Record<ReadoutBucket, ReadoutSignal[]> {
  return items.reduce<Record<ReadoutBucket, ReadoutSignal[]>>((acc, item) => {
    acc[item.bucket].push(item);
    return acc;
  }, {
    canonical: [],
    candidate: [],
    inferred: [],
    fallback: [],
  });
}

function bucketCountsFromLineage(lineage: Record<ReadoutBucket, ReadoutSignal[]>): Record<ReadoutBucket, number> {
  return {
    canonical: lineage.canonical.length,
    candidate: lineage.candidate.length,
    inferred: lineage.inferred.length,
    fallback: lineage.fallback.length,
  };
}

function uniqueStrings(values: string[]) {
  return [...new Set(values.map((value) => String(value ?? '').trim()).filter(Boolean))];
}

function formatValue(value: Tier1Readout['cvss']): string | undefined {
  if (value == null) return undefined;
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.base_score === 'number' || typeof record.base_score === 'string') return String(record.base_score);
    if (typeof record.score === 'number' || typeof record.score === 'string') return String(record.score);
  }
  return undefined;
}

import { buildTier1ReadoutPresentation } from './tier1ReadoutLayout.ts';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function runTier1ReadoutLayoutContractFixture(): void {
  const presentation = buildTier1ReadoutPresentation({
    title: 'Tier 1 Analyst Readout · CVE-2026-4342',
    bullets: ['Bullet 1', 'Bullet 2'],
    summary: 'Canonical summary for CVE-2026-4342.',
    severity: 'high',
    cvss: 9.8,
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    confidence: 'high',
    provenance: 'canonical',
    review_status: 'approved',
    mode: 'cve',
    associated_cves: ['CVE-2026-4342'],
    attack_techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', justification: 'Direct execution path', provenance: 'canonical', confidence: 'high', review_status: 'approved' },
    ],
    d3fend_controls: [
      { id: 'D3-NTF', name: 'Network Traffic Filtering', justification: 'Restrict reachability', provenance: 'canonical', confidence: 'high', review_status: 'approved' },
    ],
    compensating_controls: [
      { id: 'CC-1', label: 'Patch', text: 'Apply vendor patch', provenance: 'derived', confidence: 'medium', review_status: 'candidate' },
    ],
    detection_guidance: [
      { id: 'DET-1', label: 'Detection', text: 'Monitor command execution', provenance: 'inferred', confidence: 'medium', review_status: 'candidate' },
      { id: 'DET-2', label: 'Detection', text: 'Watch for web shells', provenance: 'derived', confidence: 'medium', review_status: 'candidate' },
    ],
    evidence_to_review: [
      { id: 'EV-1', label: 'Evidence', text: 'Proxy logs', provenance: 'derived', confidence: 'medium', review_status: 'candidate' },
    ],
    gaps: [
      { id: 'GAP-1', label: 'Gap', text: 'Missing telemetry', provenance: 'fallback', confidence: 'low', review_status: 'candidate' },
    ],
    risk_acceptance_matrix: [
      { id: 'RISK-1', label: 'Minimal acceptance', minimum_controls: ['Patch', 'Monitor'], rationale: 'Need validation', provenance: 'derived', confidence: 'medium', review_status: 'candidate' },
    ],
    copy_paste_10_lines: ['line 1', 'line 2'],
    checklist: ['Confirm exposure', 'Validate telemetry', 'Escalate if exploited'],
    escalation_criteria: ['No telemetry after validation window'],
    source_ref: 'fixture:source',
    soc_action_pack: {
      attack_techniques: [],
      d3fend_controls: [],
      compensating_controls: [],
      detection_rules: [],
      evidence_to_review: [],
      ioc_candidates: [],
      gaps: [],
      risk_acceptance_matrix: [],
    },
  });

  assert(presentation.visibleSectionKeys.length === 6, 'readout main surface must stay focused on six visible sections');
  assert(presentation.collapsedSectionKeys.includes('lineage'), 'lineage must stay collapsed');
  assert(presentation.collapsedSectionKeys.includes('supporting'), 'supporting content must stay collapsed');
  assert(presentation.collapsedSectionKeys.includes('copy'), 'copy block must stay collapsed');
  assert(presentation.topSections.every((section) => section.items.length <= 3), 'top sections must cap visible items at 3');
  assert(presentation.lineage.canonical.length > 0, 'canonical bucket should exist');
  assert(presentation.lineage.candidate.length > 0, 'candidate bucket should exist');
  assert(presentation.lineage.inferred.length > 0, 'inferred bucket should exist');
  assert(presentation.lineage.fallback.length > 0, 'fallback bucket should exist');
}

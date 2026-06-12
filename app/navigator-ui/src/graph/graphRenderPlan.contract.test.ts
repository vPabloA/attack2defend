import { buildGraphRenderPlan, GRAPH_ALTERNATIVE_LIMIT } from './graphRenderPlan.ts';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function runGraphRenderPlanContractFixture(): void {
  const nodes = [
    { id: 'CVE-2026-4342', layer: 'cve' as const, label: 'CVE-2026-4342' },
    { id: 'CWE-20', layer: 'cwe' as const, label: 'CWE-20', badge: 'official' },
    { id: 'CWE-79', layer: 'cwe' as const, label: 'CWE-79', badge: 'candidate' },
    { id: 'CWE-89', layer: 'cwe' as const, label: 'CWE-89', badge: 'analytical_inferred' },
    { id: 'CWE-94', layer: 'cwe' as const, label: 'CWE-94', badge: 'baseline' },
    { id: 'CWE-999', layer: 'cwe' as const, label: 'CWE-999', badge: 'unknown' },
    { id: 'CWE-1000', layer: 'cwe' as const, label: 'CWE-1000', badge: 'unknown' },
    { id: 'CAPEC-1', layer: 'capec' as const, label: 'CAPEC-1', badge: 'candidate' },
    { id: 'T1059', layer: 'attack' as const, label: 'T1059', badge: 'candidate' },
    { id: 'D3-NTF', layer: 'd3fend' as const, label: 'D3-NTF', badge: 'official' },
  ];

  const plan = buildGraphRenderPlan({
    nodes,
    canonicalPathIds: ['CVE-2026-4342', 'CWE-20', 'CAPEC-1', 'T1059', 'D3-NTF'],
  });

  assert(plan.stages[1].nodes.length <= GRAPH_ALTERNATIVE_LIMIT + 1, 'CWE stage must cap alternatives to canonical + 3');
  assert(plan.stages[1].hiddenAlternatives === 2, 'CWE stage should hide overflow alternatives');
  assert(plan.visibleNodeCount <= nodes.length, 'visible node count must never exceed input nodes');
  assert(plan.hiddenAlternativeCount === 2, 'hidden alternative count should reflect the capped overflow');
  assert(plan.contentHeight >= 640, 'graph viewport must remain fixed-height and scrollable');
}

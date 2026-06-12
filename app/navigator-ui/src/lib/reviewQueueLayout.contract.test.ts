import { buildReviewQueuePresentation, REVIEW_QUEUE_VISIBLE_LIMIT } from './reviewQueueLayout.ts';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function runReviewQueueLayoutContractFixture(): void {
  const items = Array.from({ length: 40 }, (_, index) => ({
    id: `CVE-2026-${String(index + 1).padStart(4, '0')}`,
    label: `CVE-${index + 1}`,
    review_status: 'candidate' as const,
    provenance: index % 2 === 0 ? 'canonical' : 'derived',
    confidence: 'medium',
    reason: 'Fixture review item',
  }));

  const collapsed = buildReviewQueuePresentation(items);
  const expanded = buildReviewQueuePresentation(items, true);

  assert(collapsed.visibleItems.length === REVIEW_QUEUE_VISIBLE_LIMIT, 'collapsed queue must cap visible items at 25');
  assert(collapsed.hiddenCount === 15, 'collapsed queue must report hidden overflow');
  assert(collapsed.hasMore === true, 'collapsed queue must expose more items when overflow exists');
  assert(expanded.visibleItems.length === 40, 'expanded queue must show all items');
}

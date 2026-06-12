import type { ReviewQueueItem } from '../types/attack2defend';

export const REVIEW_QUEUE_VISIBLE_LIMIT = 25;

export type ReviewQueuePresentation = {
  visibleItems: ReviewQueueItem[];
  hiddenCount: number;
  limit: number;
  expanded: boolean;
  hasMore: boolean;
  visibleCount: number;
};

export function buildReviewQueuePresentation(items: ReviewQueueItem[], expanded = false, limit = REVIEW_QUEUE_VISIBLE_LIMIT): ReviewQueuePresentation {
  const visibleCount = expanded ? items.length : Math.min(items.length, limit);
  const visibleItems = items.slice(0, visibleCount);
  const hiddenCount = Math.max(0, items.length - visibleCount);
  return {
    visibleItems,
    hiddenCount,
    limit,
    expanded,
    hasMore: hiddenCount > 0,
    visibleCount,
  };
}

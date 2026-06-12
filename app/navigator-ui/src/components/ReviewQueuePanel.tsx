import { useEffect, useMemo, useState } from 'react';
import type { ReviewFilter, ReviewQueueItem } from '../types/attack2defend';
import { buildReviewQueuePresentation } from '../lib/reviewQueueLayout.ts';

export interface ReviewQueuePanelProps {
  items: ReviewQueueItem[];
  filter: ReviewFilter;
  onFilterChange: (filter: ReviewFilter) => void;
  onPromote: (id: string) => void;
  onReject: (id: string) => void;
  onSelect: (id: string) => void;
  selectedId?: string;
}

const FILTERS: Array<{ id: ReviewFilter; label: string; hint: string }> = [
  { id: 'pending', label: 'Pending approval', hint: 'Default triage queue' },
  { id: 'all', label: 'All', hint: 'Show every queue item' },
  { id: 'canonical', label: 'Canonical only', hint: 'Keep approved canonical items' },
  { id: 'ai_inferred', label: 'AI-inferred', hint: 'Keep derived or inferred items' },
];

export function ReviewQueuePanel({ items, filter, onFilterChange, onPromote, onReject, onSelect, selectedId }: ReviewQueuePanelProps) {
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    setExpanded(false);
  }, [filter, items.length]);

  const presentation = useMemo(() => buildReviewQueuePresentation(items, expanded), [items, expanded]);

  return (
    <section className="a2d-side-card a2d-review-panel">
      <div className="a2d-panel-title">
        <h3>Review queue</h3>
        <span>{presentation.visibleCount}{presentation.hiddenCount > 0 ? ` / ${items.length}` : ''}</span>
      </div>
      <div className="a2d-filter-strip a2d-review-filters">
        {FILTERS.map((item) => (
          <button key={item.id} type="button" className={filter === item.id ? 'active' : ''} onClick={() => onFilterChange(item.id)} title={item.hint}>
            {item.label}
          </button>
        ))}
      </div>
      <div className="a2d-review-list a2d-review-list-scroll">
        {presentation.visibleItems.length === 0 && (
          <p className="a2d-empty-state">No queue items match the current filter.</p>
        )}
        {presentation.visibleItems.map((item) => (
          <article key={item.id} className={`a2d-review-item ${selectedId === item.id ? 'selected' : ''}`}>
            <header>
              <div>
                <strong>{item.label}</strong>
                <span>{item.id}</span>
              </div>
              <div className="a2d-review-badges">
                <em>{item.review_status}</em>
                {item.provenance && <em>{item.provenance}</em>}
                {item.confidence && <em>{item.confidence}</em>}
              </div>
            </header>
            {item.reason && <p>{item.reason}</p>}
            <footer>
              <button type="button" onClick={() => onSelect(item.id)}>View</button>
              <button type="button" onClick={() => onPromote(item.id)}>Promote</button>
              <button type="button" onClick={() => onReject(item.id)}>Reject</button>
            </footer>
          </article>
        ))}
      </div>
      {presentation.hasMore && (
        <button
          type="button"
          className="a2d-review-more"
          onClick={() => setExpanded((current) => !current)}
          aria-expanded={expanded}
        >
          {expanded ? 'Ver menos' : 'Ver más'}
        </button>
      )}
    </section>
  );
}

import type { ReviewFilter, ReviewQueueItem } from '../types/attack2defend';

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
  { id: 'all', label: 'All', hint: 'Show every queue item' },
  { id: 'canonical', label: 'Canonical only', hint: 'Keep approved canonical items' },
  { id: 'ai_inferred', label: 'AI-inferred', hint: 'Keep derived or inferred items' },
  { id: 'pending', label: 'Pending approval', hint: 'Keep items awaiting review' },
];

export function ReviewQueuePanel({ items, filter, onFilterChange, onPromote, onReject, onSelect, selectedId }: ReviewQueuePanelProps) {
  return (
    <section className="a2d-side-card a2d-review-panel">
      <div className="a2d-panel-title">
        <h3>Review queue</h3>
        <span>{items.length}</span>
      </div>
      <div className="a2d-filter-strip a2d-review-filters">
        {FILTERS.map((item) => (
          <button key={item.id} type="button" className={filter === item.id ? 'active' : ''} onClick={() => onFilterChange(item.id)} title={item.hint}>
            {item.label}
          </button>
        ))}
      </div>
      <div className="a2d-review-list">
        {items.length === 0 && (
          <p className="a2d-empty-state">No queue items match the current filter.</p>
        )}
        {items.map((item) => (
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
    </section>
  );
}

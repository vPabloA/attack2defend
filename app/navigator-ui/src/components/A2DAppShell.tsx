import type { RouteViewModel } from '../lib/routeViewModel';
import { CoherencePanel } from './CoherencePanel';
import { ConfidenceLegend } from './ConfidenceLegend';
import { CveRouteSearch } from './CveRouteSearch';
import { MappingGraph2D } from './MappingGraph2D';
import { QuickContextPanel } from './QuickContextPanel';
import { Tier1ReadoutPanel } from './Tier1ReadoutPanel';
import { ReviewQueuePanel } from './ReviewQueuePanel';
import type { BundleSummary, ReviewFilter, ReviewQueueItem, SearchContext } from '../types/attack2defend';
import '../a2dShell.css';

export interface A2DAppShellProps {
  query: string;
  batchInput: string;
  viewModel: RouteViewModel;
  bundleSummary: BundleSummary;
  reviewQueue: ReviewQueueItem[];
  reviewFilter: ReviewFilter;
  searchContext: SearchContext;
  showStats: boolean;
  onQueryChange: (value: string) => void;
  onAnalyze: () => void;
  onBatchInputChange: (value: string) => void;
  onBatchAnalyze: () => void;
  onReviewFilterChange: (value: ReviewFilter) => void;
  onToggleStats: () => void;
  onCopyReadout: () => void;
  onExportMarkdown: () => void;
  onPromote: (id?: string) => void;
  onReject: (id?: string) => void;
  onReset: () => void;
  onSelectReviewItem: (id: string) => void;
  selectedId?: string | null;
  statusMessage?: string;
  errorMessage?: string;
}

export function A2DAppShell({
  query,
  batchInput,
  viewModel,
  bundleSummary,
  reviewQueue,
  reviewFilter,
  searchContext,
  showStats,
  onQueryChange,
  onAnalyze,
  onBatchInputChange,
  onBatchAnalyze,
  onReviewFilterChange,
  onToggleStats,
  onCopyReadout,
  onExportMarkdown,
  onPromote,
  onReject,
  onReset,
  onSelectReviewItem,
  selectedId,
  statusMessage,
  errorMessage,
}: A2DAppShellProps) {
  return (
    <section className="a2d-shell" aria-label="Attack2Defend SOC Tier 1 shell">
      <header className="a2d-topbar">
        <div className="a2d-brand">
          <div className="a2d-brand-mark" aria-hidden="true">A2D</div>
          <div>
            <h1>Attack2Defend</h1>
            <span>SOC Platform</span>
          </div>
        </div>

        <CveRouteSearch
          value={query}
          placeholder="CVE-2021-44228"
          onChange={onQueryChange}
          onAnalyze={onAnalyze}
        />

      </header>

      <div className="a2d-status-strip" aria-label="Bundle status and search context">
        <div className="a2d-status-pill"><strong>{bundleSummary.bundle_version ?? 'unknown'}</strong><span>Bundle</span></div>
        <div className="a2d-status-pill"><strong>{bundleSummary.generated_at ?? 'unknown'}</strong><span>Generated</span></div>
        <div className="a2d-status-pill"><strong>{bundleSummary.cve_count}</strong><span>CVEs</span></div>
        <div className="a2d-status-pill"><strong>{bundleSummary.route_count}</strong><span>Routes</span></div>
        <div className="a2d-status-pill"><strong>{bundleSummary.review_queue_count}</strong><span>Queue</span></div>
        <div className="a2d-status-pill"><strong>{searchContext.mode}</strong><span>Search</span></div>
        <button type="button" className="a2d-stats-button" onClick={onToggleStats}>
          {showStats ? 'Hide stats' : 'Stats'}
        </button>
      </div>

      <div className="a2d-search-controls">
        <div className="a2d-batch-card">
          <div className="a2d-panel-title">
            <h3>Batch import</h3>
            <span>{searchContext.selected_ids.length} selected</span>
          </div>
          <textarea
            className="a2d-batch-input"
            value={batchInput}
            onChange={(event) => onBatchInputChange(event.target.value)}
            placeholder="Paste CVE, CWE, CAPEC, ATT&CK or D3FEND identifiers one per line or separated by commas."
          />
          <div className="a2d-action-row">
            <button type="button" onClick={onBatchAnalyze}>Analyze batch</button>
            <button type="button" onClick={onReset}>Clean / reset</button>
          </div>
        </div>
        <div className="a2d-filter-strip">
          {(['pending', 'all', 'canonical', 'ai_inferred'] as ReviewFilter[]).map((item) => (
            <button key={item} type="button" className={reviewFilter === item ? 'active' : ''} onClick={() => onReviewFilterChange(item)}>
              {item === 'pending' ? 'Pending approval' : item === 'all' ? 'All' : item === 'canonical' ? 'Canonical only' : 'AI-inferred'}
            </button>
          ))}
        </div>
      </div>

      <div className="a2d-subtitle">
        <strong>CVE -&gt; CWE -&gt; CAPEC -&gt; ATT&amp;CK -&gt; D3FEND</strong>
        <span>{searchContext.message || (viewModel.found ? 'Ruta resuelta desde bundle local' : 'Esperando input valido del bundle local')}</span>
      </div>

      {(statusMessage || errorMessage) && (
        <div className="a2d-analysis-status" role={errorMessage ? 'alert' : 'status'} aria-live="polite">
          {statusMessage && <p className="a2d-status-message">{statusMessage}</p>}
          {errorMessage && <p className="a2d-error-message">{errorMessage}</p>}
        </div>
      )}

      {showStats && (
        <section className="a2d-stats-panel">
          <div className="a2d-metadata-grid">
            <div><span>Node count</span><strong>{bundleSummary.node_count}</strong></div>
            <div><span>Edge count</span><strong>{bundleSummary.edge_count}</strong></div>
            <div><span>Route count</span><strong>{bundleSummary.route_count}</strong></div>
            <div><span>Review queue</span><strong>{bundleSummary.review_queue_count}</strong></div>
            <div><span>Last sync</span><strong>{bundleSummary.last_sync ?? 'unknown'}</strong></div>
            <div><span>Provenance</span><strong>{bundleSummary.provenance ?? 'canonical'}</strong></div>
          </div>
        </section>
      )}

      <div className="a2d-workspace">
        <div className="a2d-main-column">
          <MappingGraph2D
            nodes={viewModel.nodes}
            edges={viewModel.edges}
            canonicalPath={viewModel.canonicalPath}
            warnings={viewModel.warnings}
          />
          <ConfidenceLegend />
        </div>
        <aside className="a2d-right-stack">
          <Tier1ReadoutPanel
            readout={viewModel.tier1Readout}
            warnings={viewModel.warnings}
            onCopy={onCopyReadout}
            onExportMarkdown={onExportMarkdown}
            onPromote={() => onPromote(selectedId ?? undefined)}
            onReject={() => onReject(selectedId ?? undefined)}
            onReset={onReset}
          />
          <ReviewQueuePanel
            items={reviewQueue}
            filter={reviewFilter}
            onFilterChange={onReviewFilterChange}
            onPromote={onPromote}
            onReject={onReject}
            onSelect={onSelectReviewItem}
            selectedId={selectedId ?? undefined}
          />
          <CoherencePanel items={viewModel.coherence} />
          <QuickContextPanel context={viewModel.quickContext} warnings={viewModel.warnings} />
        </aside>
      </div>
    </section>
  );
}

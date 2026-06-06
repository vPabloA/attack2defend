import type { RouteViewModel } from '../lib/routeViewModel';
import type { ResolutionStatus, ResolutionStep } from '../lib/routeOrchestratorClient';
import { CoherencePanel } from './CoherencePanel';
import { ConfidenceLegend } from './ConfidenceLegend';
import { CveRouteSearch } from './CveRouteSearch';
import { MappingGraph2D } from './MappingGraph2D';
import { QuickContextPanel } from './QuickContextPanel';
import { ResolutionProgressPanel } from './ResolutionProgressPanel';
import { Tier1ReadoutPanel } from './Tier1ReadoutPanel';
import '../a2dShell.css';

export interface A2DAppShellProps {
  query: string;
  viewModel: RouteViewModel;
  onQueryChange: (value: string) => void;
  onAnalyze: () => void;
  searchError?: string;
  resolutionStatus?: ResolutionStatus;
  resolutionSteps?: ResolutionStep[];
  resolutionProgress?: number;
  resolutionMessage?: string;
  resolutionWarnings?: string[];
  resolutionError?: string;
  isPreview?: boolean;
  onRetryResolution?: () => void;
}

const SHOW_RESOLUTION_STATUSES: ResolutionStatus[] = [
  'local_not_found',
  'queued',
  'running',
  'completed',
  'completed_with_gaps',
  'failed',
  'disabled',
];

export function A2DAppShell({
  query,
  viewModel,
  onQueryChange,
  onAnalyze,
  searchError,
  resolutionStatus,
  resolutionSteps = [],
  resolutionProgress = 0,
  resolutionMessage,
  resolutionWarnings = [],
  resolutionError,
  isPreview = false,
  onRetryResolution,
}: A2DAppShellProps) {
  const showResolutionPanel = resolutionStatus !== undefined && SHOW_RESOLUTION_STATUSES.includes(resolutionStatus);
  const showGraph = viewModel.found || isPreview;
  const subtitleStatus = viewModel.found
    ? isPreview
      ? 'Preview — not from canonical bundle'
      : 'Ruta resuelta desde bundle local'
    : 'Esperando input valido del bundle local';

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
          resolutionStatus={resolutionStatus}
        />

        <div className="a2d-chips" aria-label="Platform attributes">
          <span className="a2d-chip a2d-chip-blue">SOC Tier 1</span>
          <span className="a2d-chip a2d-chip-purple">Single Platform</span>
          <span className="a2d-chip a2d-chip-blue">Static-First</span>
          <span className="a2d-chip a2d-chip-green">Actionable Output</span>
        </div>
      </header>

      <div className="a2d-subtitle">
        <strong>CVE -&gt; CWE -&gt; CAPEC -&gt; ATT&amp;CK -&gt; D3FEND</strong>
        <span>{subtitleStatus}</span>
        {isPreview && <span className="a2d-preview-badge">Preview / Not Canonical</span>}
      </div>

      {searchError && !showResolutionPanel && (
        <div className="a2d-search-error" role="alert">{searchError}</div>
      )}

      {showResolutionPanel && resolutionStatus && (
        <ResolutionProgressPanel
          input={query}
          status={resolutionStatus}
          steps={resolutionSteps}
          progress={resolutionProgress}
          message={resolutionMessage}
          warnings={resolutionWarnings}
          error={resolutionError}
          isPreview={isPreview}
          onRetry={onRetryResolution}
        />
      )}

      {showGraph && (
        <div className="a2d-workspace">
          <div className="a2d-main-column">
            <MappingGraph2D
              nodes={viewModel.nodes}
              edges={viewModel.edges}
              canonicalPath={viewModel.canonicalPath}
              warnings={viewModel.warnings}
              isPreview={isPreview}
            />
            <ConfidenceLegend />
          </div>
          <aside className="a2d-right-stack">
            <Tier1ReadoutPanel readout={viewModel.tier1Readout} warnings={viewModel.warnings} />
            <CoherencePanel items={viewModel.coherence} />
            <QuickContextPanel context={viewModel.quickContext} warnings={viewModel.warnings} />
          </aside>
        </div>
      )}
    </section>
  );
}

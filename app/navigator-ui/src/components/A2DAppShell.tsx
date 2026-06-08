import type { RouteViewModel } from '../lib/routeViewModel';
import { CoherencePanel } from './CoherencePanel';
import { ConfidenceLegend } from './ConfidenceLegend';
import { CveRouteSearch } from './CveRouteSearch';
import { MappingGraph2D } from './MappingGraph2D';
import { QuickContextPanel } from './QuickContextPanel';
import { Tier1ReadoutPanel } from './Tier1ReadoutPanel';
import '../a2dShell.css';

export interface A2DAppShellProps {
  query: string;
  viewModel: RouteViewModel;
  onQueryChange: (value: string) => void;
  onAnalyze: () => void;
  statusMessage?: string;
  errorMessage?: string;
}

export function A2DAppShell({ query, viewModel, onQueryChange, onAnalyze, statusMessage, errorMessage }: A2DAppShellProps) {
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

      <div className="a2d-subtitle">
        <strong>CVE -&gt; CWE -&gt; CAPEC -&gt; ATT&amp;CK -&gt; D3FEND</strong>
        <span>{viewModel.found ? 'Ruta resuelta desde bundle local' : 'Esperando input valido del bundle local'}</span>
      </div>

      {(statusMessage || errorMessage) && (
        <div className="a2d-analysis-status" role={errorMessage ? 'alert' : 'status'} aria-live="polite">
          {statusMessage && <p className="a2d-status-message">{statusMessage}</p>}
          {errorMessage && <p className="a2d-error-message">{errorMessage}</p>}
        </div>
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
          <Tier1ReadoutPanel readout={viewModel.tier1Readout} warnings={viewModel.warnings} />
          <CoherencePanel items={viewModel.coherence} />
          <QuickContextPanel context={viewModel.quickContext} warnings={viewModel.warnings} />
        </aside>
      </div>
    </section>
  );
}

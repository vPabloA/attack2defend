import type { ResolutionStatus, ResolutionStep } from '../lib/routeOrchestratorClient';

export interface ResolutionProgressPanelProps {
  input: string;
  status: ResolutionStatus;
  steps: ResolutionStep[];
  progress: number;
  message?: string;
  warnings?: string[];
  error?: string;
  isPreview?: boolean;
  onRetry?: () => void;
}

const statusLabels: Partial<Record<ResolutionStatus, string>> = {
  local_not_found: 'Not found in local bundle',
  queued: 'Resolution queued',
  running: 'Resolving route...',
  completed: 'Preview ready',
  completed_with_gaps: 'Preview ready (with gaps)',
  failed: 'Resolution failed',
  disabled: 'Resolution disabled',
};

const stepStatusIcon: Record<ResolutionStep['status'], string> = {
  pending: '○',
  running: '◎',
  completed: '✓',
  failed: '✕',
  skipped: '—',
};

export function ResolutionProgressPanel({
  input,
  status,
  steps,
  progress,
  message,
  warnings = [],
  error,
  isPreview = false,
  onRetry,
}: ResolutionProgressPanelProps) {
  const statusLabel = statusLabels[status] ?? status;
  const isBusy = status === 'queued' || status === 'running';
  const isFailed = status === 'failed';
  const isDisabled = status === 'disabled';
  const isDone = status === 'completed' || status === 'completed_with_gaps';

  return (
    <section
      className={`a2d-resolution-panel${isFailed ? ' a2d-resolution-failed' : ''}${isDisabled ? ' a2d-resolution-disabled' : ''}${isDone ? ' a2d-resolution-done' : ''}${isBusy ? ' a2d-resolution-busy' : ''}`}
      aria-live="polite"
      aria-busy={isBusy}
    >
      <div className="a2d-resolution-header">
        <div className="a2d-resolution-input">
          <span className="a2d-resolution-input-label">Input</span>
          <code>{input}</code>
        </div>
        <div className="a2d-resolution-status-row">
          <span className={`a2d-resolution-status-badge a2d-resolution-status-${status}`}>
            {statusLabel}
          </span>
          {isPreview && (
            <span className="a2d-preview-badge a2d-preview-badge-prominent">
              Preview / Not Canonical
            </span>
          )}
        </div>
      </div>

      {message && (
        <p className="a2d-resolution-message">{message}</p>
      )}

      {isDisabled && (
        <p className="a2d-resolution-disabled-msg">
          On-demand route resolution is disabled. The input is not present in the local bundle.
        </p>
      )}

      {isBusy && (
        <div className="a2d-resolution-progress-bar" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
          <div className="a2d-resolution-progress-fill" style={{ width: `${progress}%` }} />
          <span>{progress}%</span>
        </div>
      )}

      {steps.length > 0 && !isDisabled && (
        <ol className="a2d-resolution-steps">
          {steps.map((step) => (
            <li
              key={step.id}
              className={`a2d-resolution-step a2d-step-${step.status}`}
              aria-current={step.status === 'running' ? 'step' : undefined}
            >
              <span className="a2d-step-icon">{stepStatusIcon[step.status]}</span>
              <span className="a2d-step-label">{step.label}</span>
              {step.message && <span className="a2d-step-msg">{step.message}</span>}
            </li>
          ))}
        </ol>
      )}

      {error && (
        <div className="a2d-resolution-error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {warnings.length > 0 && (
        <ul className="a2d-resolution-warnings">
          {warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}

      {(isFailed || (status === 'local_not_found' && !isBusy)) && onRetry && (
        <button type="button" className="a2d-resolution-retry" onClick={onRetry}>
          Retry resolution
        </button>
      )}
    </section>
  );
}

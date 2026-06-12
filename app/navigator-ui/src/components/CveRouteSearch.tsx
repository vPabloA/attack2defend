import type { ResolutionStatus } from '../lib/routeOrchestratorClient';

export interface CveRouteSearchProps {
  value: string;
  placeholder?: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  disabled?: boolean;
  resolutionStatus?: ResolutionStatus;
}

const busyStatuses: ResolutionStatus[] = ['queued', 'running'];

export function CveRouteSearch({ value, placeholder, onChange, onAnalyze, disabled, resolutionStatus }: CveRouteSearchProps) {
  const isBusy = resolutionStatus !== undefined && busyStatuses.includes(resolutionStatus);
  const isDisabled = disabled || isBusy;
  const buttonLabel = isBusy ? 'Analyzing...' : 'Analyze';

  return (
    <div className="a2d-searchbar">
      <label htmlFor="a2d-route-search">Input CVE:</label>
      <input
        id="a2d-route-search"
        value={value}
        placeholder={placeholder ?? 'CVE-2021-44228 or H4sIA...'}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => event.key === 'Enter' && !isDisabled && onAnalyze()}
        disabled={isDisabled}
        aria-busy={isBusy}
      />
      <button type="button" onClick={onAnalyze} disabled={isDisabled} aria-busy={isBusy}>
        {buttonLabel}
      </button>
    </div>
  );
}

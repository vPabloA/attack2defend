export interface CveRouteSearchProps {
  value: string;
  placeholder?: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  disabled?: boolean;
}

export function CveRouteSearch({ value, placeholder, onChange, onAnalyze, disabled }: CveRouteSearchProps) {
  return (
    <div className="a2d-searchbar">
      <label htmlFor="a2d-route-search">Input CVE:</label>
      <input
        id="a2d-route-search"
        value={value}
        placeholder={placeholder ?? 'CVE-2021-44228'}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => event.key === 'Enter' && onAnalyze()}
        disabled={disabled}
      />
      <button type="button" onClick={onAnalyze} disabled={disabled}>
        Analyze
      </button>
    </div>
  );
}

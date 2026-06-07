import type { PreviewRouteArtifact, RouteLayer } from './routeViewModel';

export type ResolutionStatus =
  | 'idle'
  | 'local_found'
  | 'local_not_found'
  | 'queued'
  | 'running'
  | 'completed'
  | 'completed_with_gaps'
  | 'failed'
  | 'disabled';

export type ResolutionStepId =
  | 'normalize'
  | 'resolve_cve'
  | 'resolve_cwe'
  | 'map_capec'
  | 'map_attack'
  | 'map_d3fend'
  | 'validate'
  | 'publish_preview';

export interface ResolutionStep {
  id: ResolutionStepId;
  label: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  message?: string;
}

export type RouteOrchestratorMode = 'disabled' | 'mock' | 'api';

export interface CreateRouteResolutionJobRequest {
  input: string;
  mode: 'public_safe' | 'local_only';
  include_d3fend: boolean;
  include_actions: boolean;
  persist: boolean;
}

export interface CreateRouteResolutionJobResponse {
  job_id: string;
  status: ResolutionStatus;
  input: string;
  message?: string;
}

export interface RouteResolutionJobStatus {
  job_id: string;
  input: string;
  status: ResolutionStatus;
  current_step?: ResolutionStepId;
  progress: number;
  steps: ResolutionStep[];
  preview_artifact?: PreviewRouteArtifact;
  warnings?: string[];
  error?: string;
}

const STEP_LABELS: Record<ResolutionStepId, string> = {
  normalize: 'Normalizing input',
  resolve_cve: 'Resolving CVE metadata',
  resolve_cwe: 'Resolving CWE weakness',
  map_capec: 'Mapping CAPEC attack patterns',
  map_attack: 'Mapping ATT&CK techniques',
  map_d3fend: 'Mapping D3FEND countermeasures',
  validate: 'Validating preview route',
  publish_preview: 'Publishing preview artifact',
};

const STEP_ORDER: ResolutionStepId[] = [
  'normalize',
  'resolve_cve',
  'resolve_cwe',
  'map_capec',
  'map_attack',
  'map_d3fend',
  'validate',
  'publish_preview',
];

function makeInitialSteps(): ResolutionStep[] {
  return STEP_ORDER.map((id) => ({ id, label: STEP_LABELS[id], status: 'pending' as const }));
}

function getOrchestratorMode(): RouteOrchestratorMode {
  const raw = (import.meta.env.VITE_A2D_ROUTE_ORCHESTRATOR ?? 'disabled').toLowerCase().trim();
  if (raw === 'mock' || raw === 'api') return raw;
  return 'disabled';
}

export function getOrchestratorModePublic(): RouteOrchestratorMode {
  return getOrchestratorMode();
}

export type StepCallback = (steps: ResolutionStep[], progress: number) => void;

export async function startRouteResolution(
  input: string,
  onStep: StepCallback,
): Promise<RouteResolutionJobStatus> {
  const mode = getOrchestratorMode();

  if (mode === 'disabled') {
    const steps = makeInitialSteps().map((s) => ({ ...s, status: 'skipped' as const }));
    return {
      job_id: 'disabled',
      input,
      status: 'disabled',
      progress: 0,
      steps,
      warnings: ['On-demand route resolution is disabled. The input is not present in the local bundle.'],
    };
  }

  if (mode === 'mock') {
    return runMockResolution(input, onStep);
  }

  return runApiResolution(input, onStep);
}

async function runMockResolution(input: string, onStep: StepCallback): Promise<RouteResolutionJobStatus> {
  const steps = makeInitialSteps();
  const jobId = `mock-${Date.now()}`;
  const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  for (let i = 0; i < steps.length; i++) {
    steps[i] = { ...steps[i], status: 'running' };
    const progress = Math.round(((i + 0.5) / steps.length) * 100);
    onStep([...steps], progress);
    await delay(380 + Math.random() * 220);
    steps[i] = { ...steps[i], status: 'completed' };
    onStep([...steps], Math.round(((i + 1) / steps.length) * 100));
  }

  const artifact = buildMockPreviewArtifact(input);
  const hasD3fend = artifact.nodes.some((n) => n.type === 'd3fend');

  return {
    job_id: jobId,
    input,
    status: hasD3fend ? 'completed' : 'completed_with_gaps',
    progress: 100,
    steps,
    preview_artifact: artifact,
    warnings: artifact.warnings,
  };
}

function buildMockPreviewArtifact(input: string): PreviewRouteArtifact {
  const normalized = input.trim().toUpperCase();
  const now = new Date().toISOString();

  const isCve = /^CVE-\d{4}-\d+$/.test(normalized);

  const nodes: PreviewRouteArtifact['nodes'] = [];
  const edges: PreviewRouteArtifact['edges'] = [];
  const provenance: PreviewRouteArtifact['provenance'] = [];
  const warnings: string[] = [
    'Preview only — not in canonical local bundle.',
    'No CVSS score available from local bundle.',
    'CWE and CAPEC mappings are inferred, not official.',
    'ATT&CK technique is conditional — requires analyst confirmation.',
    'D3FEND countermeasure is a suggested starting point only.',
  ];

  if (isCve) {
    nodes.push({
      id: normalized,
      type: 'cve' as RouteLayer,
      name: `${normalized} (preview — not in local bundle)`,
      description: 'No description available from local bundle. Requires external validation.',
    });
    provenance.push({ id: normalized, source: 'on-demand-resolution', trust: 'unknown', note: 'Not found in local bundle' });

    const cweId = 'CWE-20';
    nodes.push({
      id: cweId,
      type: 'cwe' as RouteLayer,
      name: 'Improper Input Validation (inferred)',
      description: 'Generic CWE assigned as starting point — requires validation against official NVD data.',
    });
    edges.push({ source: normalized, target: cweId, relationship: 'has_weakness', confidence: 'low', source_ref: 'on-demand:inferred' });
    provenance.push({ id: cweId, source: 'on-demand-resolution', trust: 'inferred', note: 'Generic fallback — not official mapping' });

    const capecId = 'CAPEC-88';
    nodes.push({
      id: capecId,
      type: 'capec' as RouteLayer,
      name: 'OS Command Injection (inferred)',
      description: 'Generic CAPEC assigned as preview. Requires validation.',
    });
    edges.push({ source: cweId, target: capecId, relationship: 'weakness_enables_attack_pattern', confidence: 'low', source_ref: 'on-demand:inferred' });
    provenance.push({ id: capecId, source: 'on-demand-resolution', trust: 'inferred', note: 'Generic fallback' });

    const attackId = 'T1059';
    nodes.push({
      id: attackId,
      type: 'attack' as RouteLayer,
      name: 'Command and Scripting Interpreter (conditional)',
      description: 'ATT&CK technique assigned conditionally. Requires confirmation with threat intel.',
    });
    edges.push({ source: capecId, target: attackId, relationship: 'attack_pattern_maps_to_technique', confidence: 'low', source_ref: 'on-demand:inferred' });
    provenance.push({ id: attackId, source: 'on-demand-resolution', trust: 'inferred', note: 'Conditional — context-dependent' });

    const d3Id = 'D3-IPFIX';
    nodes.push({
      id: d3Id,
      type: 'd3fend' as RouteLayer,
      name: 'Network Traffic Filtering (suggested)',
      description: 'D3FEND countermeasure suggested as starting point. Requires validation.',
    });
    edges.push({ source: attackId, target: d3Id, relationship: 'technique_mitigated_by_countermeasure', confidence: 'low', source_ref: 'on-demand:inferred' });
    provenance.push({ id: d3Id, source: 'on-demand-resolution', trust: 'mock', note: 'Suggested countermeasure — not validated' });

    warnings.push('All mappings require validation against official MITRE CVE/CWE/ATT&CK/D3FEND sources.');
  } else {
    nodes.push({
      id: normalized,
      type: 'cve' as RouteLayer,
      name: `${normalized} (preview — unrecognized format)`,
      description: 'Input did not match a recognized CVE identifier pattern.',
    });
    provenance.push({ id: normalized, source: 'on-demand-resolution', trust: 'unknown' });
    warnings.push('Input did not match a CVE identifier pattern. Preview is minimal.');
  }

  return {
    artifact_type: 'attack2defend.preview_route',
    canonical: false,
    input,
    normalized_input: normalized,
    generated_at: now,
    source: 'mock',
    nodes,
    edges,
    warnings,
    provenance,
  };
}

async function runApiResolution(input: string, onStep: StepCallback): Promise<RouteResolutionJobStatus> {
  const steps = makeInitialSteps();

  let createResp: CreateRouteResolutionJobResponse;
  try {
    const res = await fetch('/api/route-resolution/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input,
        mode: 'public_safe',
        include_d3fend: true,
        include_actions: true,
        persist: false,
      } satisfies CreateRouteResolutionJobRequest),
    });
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    createResp = (await res.json()) as CreateRouteResolutionJobResponse;
  } catch (err) {
    const failedSteps = steps.map((s) => ({ ...s, status: 'failed' as const, message: 'API unreachable' }));
    onStep(failedSteps, 0);
    return {
      job_id: 'api-error',
      input,
      status: 'failed',
      progress: 0,
      steps: failedSteps,
      error: err instanceof Error ? err.message : 'Route resolution API is unavailable.',
      warnings: ['API mode requires same-origin /api/route-resolution/jobs endpoint.'],
    };
  }

  const jobId = createResp.job_id;
  const maxPolls = 60;
  const pollInterval = 1200;

  for (let attempt = 0; attempt < maxPolls; attempt++) {
    await new Promise<void>((resolve) => setTimeout(resolve, pollInterval));
    try {
      const res = await fetch(`/api/route-resolution/jobs/${jobId}`);
      if (!res.ok) throw new Error(`Poll error: ${res.status}`);
      const status = (await res.json()) as RouteResolutionJobStatus;
      onStep(status.steps ?? steps, status.progress ?? 0);
      if (['completed', 'completed_with_gaps', 'failed'].includes(status.status)) {
        return status;
      }
    } catch {
      // network blip — keep polling
    }
  }

  const timedOutSteps = steps.map((s) => ({ ...s, status: 'failed' as const, message: 'Timed out' }));
  return {
    job_id: jobId,
    input,
    status: 'failed',
    progress: 0,
    steps: timedOutSteps,
    error: 'Resolution timed out after 60 attempts.',
  };
}

import { getOrchestratorModePublic, startRouteResolution } from './routeOrchestratorClient';

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

export async function runRouteOrchestratorFixture(): Promise<void> {
  const mode = getOrchestratorModePublic();
  assert(['disabled', 'mock', 'api'].includes(mode), `mode should be disabled|mock|api, got: ${mode}`);

  if (mode === 'disabled') {
    const steps: unknown[] = [];
    const result = await startRouteResolution('CVE-2026-4342', (s) => steps.push(s));
    assert(result.status === 'disabled', 'disabled mode should return status=disabled');
    assert(result.warnings && result.warnings.length > 0, 'disabled mode should return warnings');
    assert(result.warnings!.some((w) => w.includes('disabled')), 'disabled warning should mention disabled');
    assert(result.preview_artifact === undefined, 'disabled mode should not return preview artifact');
  }

  if (mode === 'mock') {
    const stepUpdates: number[] = [];
    const result = await startRouteResolution('CVE-2099-9999', (_, progress) => stepUpdates.push(progress));
    assert(['completed', 'completed_with_gaps'].includes(result.status), `mock should complete, got: ${result.status}`);
    assert(result.preview_artifact !== undefined, 'mock should produce preview artifact');
    assert(result.preview_artifact!.canonical === false, 'mock artifact should not be canonical');
    assert(result.preview_artifact!.source === 'mock', 'mock artifact source should be mock');
    assert(result.preview_artifact!.nodes.length > 0, 'mock artifact should have nodes');
    assert(result.preview_artifact!.warnings.length > 0, 'mock artifact should have warnings');
    assert(stepUpdates.length > 0, 'mock should emit step updates');
    assert(stepUpdates[stepUpdates.length - 1] === 100, 'mock should reach 100% progress');
  }
}

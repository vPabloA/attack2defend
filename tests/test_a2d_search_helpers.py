from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_node_search() -> dict[str, object]:
    script = r"""
import { resolveSearchSelection } from './app/navigator-ui/src/lib/a2dSearchHelpers.js';

const bundle = {
  nodes: [
    { id: 'CVE-2021-44228', type: 'cve', name: 'Log4Shell' },
    { id: 'CWE-94', type: 'cwe', name: 'CWE-94' },
    { id: 'CAPEC-242', type: 'capec', name: 'Code Injection' },
    { id: 'T1059', type: 'attack', name: 'Command and Scripting Interpreter' },
    { id: 'D3-PSEP', type: 'd3fend', name: 'Process Sandboxing' },
  ],
  edges: [
    { source: 'CVE-2021-44228', target: 'CWE-94', relationship: 'vulnerability_has_weakness' },
    { source: 'CWE-94', target: 'CAPEC-242', relationship: 'weakness_enables_attack_pattern' },
    { source: 'CAPEC-242', target: 'T1059', relationship: 'attack_pattern_maps_to_technique' },
    { source: 'T1059', target: 'D3-PSEP', relationship: 'technique_mitigated_by_countermeasure' },
  ],
  reverse_index: {
    by_cwe: { 'CWE-94': ['CVE-2021-44228'] },
    by_capec: { 'CAPEC-242': ['CVE-2021-44228'] },
    by_attack: { 'T1059': ['CVE-2021-44228'] },
    by_d3fend: { 'D3-PSEP': ['CVE-2021-44228'] },
  },
  cves: {
    'CVE-2021-44228': {
      id: 'CVE-2021-44228',
      label: 'CVE-2021-44228',
      canonical_chain: [],
      soc_action_pack: {
        attack_techniques: [],
        d3fend_controls: [],
        compensating_controls: [],
        detection_rules: [],
        evidence_to_review: [],
        ioc_candidates: [],
        gaps: [],
        risk_acceptance_matrix: [],
      },
      tier1_readout: { title: 'CVE-2021-44228', bullets: [] },
    },
  },
};

const direct = resolveSearchSelection(bundle, 'CVE-2021-44228');
const attackReverse = resolveSearchSelection(bundle, 'T1059');
const d3Reverse = resolveSearchSelection(bundle, 'D3-PSEP');
const batch = resolveSearchSelection(bundle, 'CVE-2021-44228, T1059');

process.stdout.write(JSON.stringify({ direct, attackReverse, d3Reverse, batch }));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_search_helper_supports_direct_and_reverse_pivots() -> None:
    result = run_node_search()

    direct = result["direct"]
    attack_reverse = result["attackReverse"]
    d3_reverse = result["d3Reverse"]
    batch = result["batch"]

    assert direct["mode"] == "direct"
    assert direct["selectedIds"][0] == "CVE-2021-44228"
    assert attack_reverse["mode"] == "reverse"
    assert "CVE-2021-44228" in attack_reverse["associatedCves"]
    assert d3_reverse["mode"] == "reverse"
    assert "CVE-2021-44228" in d3_reverse["associatedCves"]
    assert batch["mode"] in {"batch", "mixed"}
    assert "CVE-2021-44228" in batch["selectedIds"]

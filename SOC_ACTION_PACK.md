# SOC Action Pack

The SOC Action Pack converts an Attack2Defend route into an operational response artifact.

## Generate

```bash
make soc-pack INPUT=CVE-2021-44228
```

## What it answers

| SOC question | Field |
|---|---|
| What is the threat chain? | `soc_pack.threat_chain` |
| What defensive objective applies? | `soc_pack.defensive_objective` |
| What should we detect? | `integration_hints.detection_candidates` |
| What evidence is needed? | `defense_readiness.evidence_required` |
| What gaps block closure? | `defense_readiness.gaps` |
| What actions should owners take? | `defense_readiness.actions` |
| What are the top mitigations? | `top_3_recommendations` |
| What supports the answer? | `audit.source_refs` |

## Important

Detection outputs are candidates, not validated rules. They require environmental validation before conversion to Detection-as-Code.

If data is missing, the pack returns `completed_with_gaps` instead of inventing evidence.

# Agent Instructions

This repository is an early foundation for Attack2Defend Navigator.

## Prime directive

Keep the system deterministic first and AI-assisted second.

```text
Route resolution is source-of-truth logic.
AI route analysis is interpretation only.
```

## Do

- Preserve simple UX: Route first, Graph second.
- Read existing docs before coding.
- Add contracts before UI complexity.
- Add tests for every resolver or mapping change.
- Separate public framework data from internal coverage data.
- Keep runtime independent from public APIs.
- Make missing evidence explicit.
- Separate confirmed evidence, inference and hypothesis.

## Do not

- Let AI invent framework mappings.
- Claim coverage without control, detection, evidence and owner.
- Add graph database before JSON is insufficient.
- Rebuild ATT&CK Navigator or D3FEND CAD in MVP.
- Depend on live NVD/D3FEND/ATT&CK calls during SOC runtime.
- Overwrite internal coverage during public data sync.

## Preferred architecture

```text
Threat Knowledge Builder
→ Local Knowledge Bundle
→ Route Resolver
→ Coverage Enricher
→ AI Route Analyst
→ Action Card / UI / Export
```

## First milestone

Deliver a working deterministic MVP for:

```text
CVE-2021-44228 → CWE → CAPEC → ATT&CK → D3FEND → CTI/TH actions
```

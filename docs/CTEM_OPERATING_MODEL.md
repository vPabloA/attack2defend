# CTEM Operating Model

Attack2Defend becomes useful in CTEM when it stops being a framework browser and becomes a decision aid.

The CTEM translation is:

```text
Exposure → likely adversary technique → expected defense → real coverage → action → validation
```

---

## CTEM loop

| CTEM phase | Attack2Defend contribution |
|---|---|
| Scope | Define assets/domains that matter: internet-facing, crown jewels, cloud, apps, APIs, identities. |
| Discover | Accept CVE/CWE/CAPEC/ATT&CK/D3FEND or manual input and build the route. |
| Prioritize | Combine exploitability, KEV, asset criticality, exposure and defensive coverage. |
| Validate | Propose validation: exploitability check, BAS, safe test, detection test, log review. |
| Mobilize | Produce actions for SOC, CTI, TH, AppSec, Infra, Cloud, IAM and GRC. |

---

## Operational decision states

Every route analysis should end in one or more of these decisions:

| Decision | Meaning |
|---|---|
| no_action | Not relevant or not applicable. |
| monitor | Watch only; no immediate remediation. |
| hunt | Create or run a threat hunting hypothesis. |
| detect | Create/modify detection logic. |
| validate | Confirm exploitability or defensive coverage. |
| mitigate | Patch, harden, isolate or compensate. |
| escalate | Potential incident or critical exposure. |
| accept_risk | Formal risk acceptance required. |

---

## Prioritization factors

| Factor | Weight guidance | Question |
|---|---:|---|
| Asset criticality | High | Does this affect a crown jewel or critical business system? |
| Exposure | High | Is it internet-facing, third-party-facing or reachable by untrusted users? |
| Exploitability | High | Is there KEV, exploit public, PoC or active exploitation? |
| ATT&CK impact | Medium | Does the route enable access, execution, credential access, exfiltration or impact? |
| D3FEND coverage | Medium | Do we have preventive, detective and response controls? |
| Evidence availability | Medium | Can we prove or disprove exploitation? |

Simple formula:

```text
Priority rises with criticality, exposure and exploitability.
Priority drops only when coverage and evidence are real.
```

---

## Output card

A useful CTEM output card should include:

```yaml
exposure_id: EXP-YYYY-NNNNN
input: CVE-YYYY-NNNNN
route:
  cwe: []
  capec: []
  attack: []
  d3fend: []
asset_context:
  asset: ""
  owner: ""
  business_criticality: unknown
  internet_exposed: unknown
coverage:
  preventive: unknown
  detective: unknown
  response: unknown
  evidence: unknown
decision: validate
priority: P2
actions_by_owner:
  cti: []
  threat_hunting: []
  soc: []
  appsec: []
  infra: []
  cloud: []
missing_evidence: []
closure_criteria: []
```

---

## CTI outputs

| Output | Purpose |
|---|---|
| PIRs | What intelligence questions need to be answered. |
| Watchlists | CVEs, vendors, products, techniques, domains/IPs. |
| TTP pack | ATT&CK techniques and likely post-exploitation chain. |
| Infrastructure notes | Callback domains, hosting, ASN, scanning infra. |
| Exposure brief | Why this matters to the organization. |

---

## Threat Hunting outputs

| Output | Purpose |
|---|---|
| Hypotheses | Structured hunting statements. |
| Data sources | Logs required to test the hypothesis. |
| Pivots | Entities and artifacts to correlate. |
| Hunt window | Time period to search. |
| Escalation criteria | Evidence that turns a hunt into an incident. |

---

## Example: Log4Shell

```text
CVE-2021-44228
→ CWE-917 / CWE-20 / CWE-502
→ CAPEC-136 / CAPEC-248
→ T1190 / T1059 / T1105 / T1071
→ D3FEND inventory, update, application hardening, network/process analysis
```

CTEM decision:

```text
If asset is internet-facing and vulnerable: VALIDATE_AND_MITIGATE.
If outbound callback or Java child process is observed: ESCALATE.
If patched but logs are missing: DETECT + HUNT + CLOSE TELEMETRY GAP.
```

---

## Closure rule

A CTEM item is not closed because the route exists.

It closes when:

1. exposure is remediated, compensated or accepted;
2. detection/evidence is sufficient for future monitoring;
3. owner signs off;
4. validation confirms risk reduction;
5. residual gaps are documented.

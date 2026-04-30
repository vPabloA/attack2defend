# UX Model

Attack2Defend must stay simple by default and powerful on demand.

The main experience is not a giant graph. The main experience is a **route**.

```text
Input → Route → Interpretation → Actions → Evidence/Gaps → Export
```

---

## Primary UX principle

```text
Route first. Graph second. MITRE native views third.
```

Why:

- analysts need fast understanding;
- CTI and TH need actionable hypotheses;
- graphs are useful for depth, not for first contact;
- native MITRE tools are valuable, but they should be linked/exported, not cloned blindly.

---

## Recommended tabs

```text
[ Route ] [ Actions ] [ Graph ] [ MITRE Views ] [ Coverage ] [ Export ]
```

| Tab | Purpose | Default? |
|---|---|---|
| Route | Linear CVE/CWE/CAPEC/ATT&CK/D3FEND path. | Yes |
| Actions | CTI, Threat Hunting, SOC, AppSec, Infra and Cloud actions. | No |
| Graph | Auto-generated graph of the selected route. | No |
| MITRE Views | Deep links and future exports to ATT&CK Navigator/D3FEND CAD. | No |
| Coverage | Controls, detections, evidence, owners and gaps. | No |
| Export | Markdown/YAML/JSON and future Navigator layer. | No |

---

## Route tab

The Route tab is inspired by NSFW and CVE2CAPEC simplicity.

```text
[ Search: CVE / CWE / CAPEC / ATT&CK / D3FEND ]

CVE        CWE        CAPEC        ATT&CK        D3FEND
----       ----       -----        ------        ------
CVE...     CWE...     CAPEC...     T1190         D3-NTA
                                   T1059         D3-PA
                                                 D3-SU
```

Selected node panel:

| Section | Content |
|---|---|
| Name | ID + official name |
| Type | CVE/CWE/CAPEC/ATT&CK/D3FEND |
| Meaning | Short explanation |
| Official link | Source link |
| Related nodes | Direct relationships |
| Route role | Why this node matters in the route |

---

## Actions tab

The Actions tab converts route into operations.

| Audience | Output |
|---|---|
| CTI | PIRs, watchlist, IoCs, vendors, exploitation context. |
| Threat Hunting | Hypotheses, pivots, data sources, hunt windows. |
| SOC | Detection candidates, escalation criteria, runbook steps. |
| AppSec | CWE/root cause, validation, remediation, dependency checks. |
| Infra/Cloud | Exposure reduction, egress control, IAM/logging validation. |

---

## Graph tab

Graph is generated automatically from the route.

Minimum graph:

```text
[CVE] → [CWE] → [CAPEC] → [ATT&CK] → [Artifact] → [D3FEND]
```

Operational graph extension:

```text
[D3FEND] → [Control] → [Detection] → [Evidence] → [Gap]
```

The graph must never be the only source of truth. It visualizes the route object.

---

## MITRE Views tab

Do not rebuild native MITRE tools in MVP.

Use:

| Native element | MVP handling |
|---|---|
| ATT&CK technique page | Deep link. |
| D3FEND technique page | Deep link. |
| ATT&CK Navigator | Export layer JSON in a later phase. |
| D3FEND CAD | Export compatible graph in a later phase. |

---

## Coverage tab

Coverage states:

| State | Meaning |
|---|---|
| covered | Control + detection + evidence + owner exist. |
| partial | At least one required element is missing. |
| missing | No known internal coverage. |
| unknown | Not evaluated yet. |
| not_applicable | Does not apply to this environment. |

Coverage is internal, curated and must not be overwritten by public data sync.

---

## Export tab

Minimum export formats:

| Format | Use |
|---|---|
| Markdown | CTI/TH/SOC report. |
| YAML | Detection-as-Code metadata. |
| JSON | API or future integration. |

Future:

| Format | Use |
|---|---|
| ATT&CK Navigator layer | Visualize selected ATT&CK techniques. |
| D3FEND CAD-compatible graph | Visualize defensive graph. |

---

## MVP screen

```text
┌─────────────────────────────────────────────┐
│ Attack2Defend Navigator                     │
│ [ Search CVE / CWE / CAPEC / ATT&CK / D3 ]  │
└─────────────────────────────────────────────┘

[ Route ] [ Actions ] [ Graph ] [ MITRE Views ] [ Coverage ] [ Export ]

┌─────────────────────────────────────────────┐
│ CVE → CWE → CAPEC → ATT&CK → D3FEND         │
└─────────────────────────────────────────────┘

┌─────────────────────┬───────────────────────┐
│ Selected Node       │ AI Route Analyst       │
│ detail + links      │ summary + actions      │
└─────────────────────┴───────────────────────┘
```

---

## UX anti-patterns

Avoid:

- graph-first UX;
- too many controls in the landing screen;
- hiding actions behind technical relationships;
- letting AI change the route;
- showing coverage without evidence;
- claiming defensive coverage without owner and validation.

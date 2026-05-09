# Attribution and Clean-Room Notes

Attack2Defend is an original static-first cyber defense navigator.

This project may compare itself against, interoperate with, or be conceptually inspired by external open-source projects and public cybersecurity frameworks. External projects are treated as references and benchmarks, not as implementation sources unless their licenses explicitly allow reuse and the reused material is recorded here.

## External project references

| Project | Use in Attack2Defend | Reuse rule |
|---|---|---|
| Galeax/CVE2CAPEC | Functional benchmark for CVE to CAPEC/ATT&CK route parity and export compatibility. | Do not copy GPL implementation code into this repository unless the licensing impact is explicitly accepted. |
| frncscrlnd/nsfw | Conceptual reference for static/offline navigation over cybersecurity mappings. | Do not copy implementation code unless license compatibility is verified. |
| alexis-/Capec2Neo4j | Conceptual reference for optional Neo4j graph import and Cypher exploration. | Reuse only if compatible with its license and recorded in NOTICE. |
| edward-playground/aidefense-framework / AIDEFEND | Conceptual reference for defensive capability views and AI-defense framing. | Treat as conceptual inspiration unless explicit reusable material is reviewed and attributed. |

## Public cybersecurity frameworks

Attack2Defend may ingest or reference public framework data such as CVE, CWE, CAPEC, MITRE ATT&CK, MITRE D3FEND, CISA KEV, EPSS, CVSS, SSVC and CPE metadata. Each generated relationship must carry edge-level provenance in the canonical bundle.

## Clean-room policy

- Prefer contract compatibility over source-code reuse.
- Keep generated bundle data auditable through `source_feed`, `source_ref` or `source_url`, `retrieved_at`, `transform_version`, `confidence`, `deterministic`, and `inferred`.
- Do not import incompatible code, generated files, datasets, or UI assets without explicit license review.
- When in doubt, build an original implementation from public specifications and document the reference here.

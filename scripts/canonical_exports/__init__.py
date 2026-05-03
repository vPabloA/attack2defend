"""Canonical mapping exports: NSFW + CVE2CAPEC parity output.

This module reads the Attack2Defend knowledge bundle and produces:

1. NSFW-style canonical mapping files
   (cve_cwe.json, cwe_capec.json, capec_attack.json, attack_defend.json,
    cve_cpe.json, cve_cvss.json, d3fend_tactics.json, tactics_techniques.json,
    kevs.txt).

2. CVE2CAPEC-style layout (database/CVE-YYYY.jsonl, resources/*.json[l],
   lastUpdate.txt, results/new_cves.jsonl).

The Navigator UI does not call public APIs at runtime; the exporter is a
builder-time transform of the local knowledge bundle.
"""

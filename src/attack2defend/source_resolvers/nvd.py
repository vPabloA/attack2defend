"""NVD CVE API 2.0 resolver.

Queries services.nvd.nist.gov/rest/json/cves/2.0 for CVE data.
Returns a normalized dict with id, description, cwe_ids, cvss, cpe, references.
Falls back to cache if the API is unreachable.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import cache as _cache

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SOURCE = "nvd"
_TIMEOUT = 15


def resolve(cve_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> dict[str, Any]:
    """Return normalized CVE data from NVD. Empty dict if unavailable."""
    cve_upper = cve_id.upper()
    if use_cache:
        cached = _cache.load(cve_upper, _SOURCE, cache_dir)
        if cached is not None:
            return cached

    data = _fetch(cve_upper)
    if data and use_cache:
        _cache.save(cve_upper, _SOURCE, data, cache_dir)
    return data or {}


def _fetch(cve_id: str) -> dict[str, Any] | None:
    url = f"{_NVD_BASE}?cveId={urllib.parse.quote(cve_id)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attack2defend/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})
    return _normalize(cve_data)


def _normalize(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve.get("id", "")

    # Description (prefer English)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CWE IDs
    cwe_ids: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # CVSS
    cvss: dict[str, Any] = {}
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss = {
                "version": data.get("version", ""),
                "baseScore": data.get("baseScore"),
                "baseSeverity": data.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vectorString": data.get("vectorString", ""),
            }
            break

    # CPE
    cpe_names: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe_names.append(match.get("criteria", ""))

    # References
    refs: list[dict[str, str]] = []
    for r in cve.get("references", []):
        refs.append({"url": r.get("url", ""), "source": r.get("source", "")})

    published = cve.get("published", "")
    status = cve.get("vulnStatus", "")

    return {
        "id": cve_id,
        "description": desc,
        "cwe_ids": list(dict.fromkeys(cwe_ids)),
        "cvss": cvss,
        "cpe": cpe_names[:20],
        "references": refs[:10],
        "published": published,
        "status": status,
        "source": "nvd",
    }

"""Vendor advisory resolver.

Extracts context from vendor/CNA references included in a CVE's NVD record.
Only reads the reference URLs already present in the source-pack — no crawling.
"""

from __future__ import annotations

from typing import Any


_KNOWN_VENDOR_PATTERNS = [
    "redis.io", "redis.com",
    "security.snyk.io", "snyk.io",
    "bugzilla.redhat.com",
    "access.redhat.com",
    "ubuntu.com/security",
    "debian.org/security",
    "github.com/advisories",
    "github.com/.*/security/advisories",
]


def extract_vendor_refs(nvd_data: dict[str, Any]) -> list[dict[str, str]]:
    """Extract advisory/vendor references from NVD source-pack data."""
    refs = nvd_data.get("references", [])
    vendor_refs: list[dict[str, str]] = []
    for ref in refs:
        url = ref.get("url", "")
        source = ref.get("source", "")
        if _is_vendor_or_advisory(url):
            vendor_refs.append({"url": url, "source": source, "type": "vendor_advisory"})
    return vendor_refs


def _is_vendor_or_advisory(url: str) -> bool:
    import re
    lower = url.lower()
    return any(re.search(p, lower) for p in _KNOWN_VENDOR_PATTERNS)


def advisory_source_ref(nvd_data: dict[str, Any]) -> str:
    """Return a single canonical source_ref string for vendor advisory provenance."""
    refs = extract_vendor_refs(nvd_data)
    if refs:
        return refs[0]["url"]
    # Fall back to first NVD reference
    all_refs = nvd_data.get("references", [])
    if all_refs:
        return all_refs[0].get("url", "nvd_reference")
    return "nvd_api"

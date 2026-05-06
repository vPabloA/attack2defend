"""Curator configuration.

Loaded from data/intelligence/curator_config.yaml (or .json).
All fields have sane defaults so it works out of the box.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class CuratorConfig:
    """Configuration for the Defense Intelligence Curator."""

    # LLM settings
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.0
    max_tokens: int = 4096

    # Gap scanning
    max_gaps_per_run: int = 50
    gap_types: list[str] = field(default_factory=lambda: [
        "missing_d3fend",    # ATT&CK technique → no D3FEND countermeasures
        "missing_capec",     # CWE node → no CAPEC attack patterns
        "missing_attack",    # CAPEC node → no ATT&CK technique
        "partial_coverage",  # semantic_route status is partial/catalog-only
        "coverage_gap",      # coverage record has non-empty gaps[]
    ])

    # Evidence gating
    confidence_threshold: str = "medium"  # min confidence to propose
    require_evidence_url: bool = True      # block promotion without URL

    # Priority heuristics
    boost_kev: bool = True          # prioritize gaps touching KEV CVEs
    boost_active_routes: bool = True  # prioritize gaps in active semantic routes

    # Output
    output_format: str = "json"

    @classmethod
    def from_file(cls, path: Path) -> "CuratorConfig":
        """Load from YAML (preferred) or JSON. Returns defaults if file absent."""
        if not path.exists():
            return cls()
        content = path.read_text(encoding="utf-8")
        data: dict = {}
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(content) or {}
        except ImportError:
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return cls()
        if not isinstance(data, dict):
            return cls()
        known = {f.name for f in _fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)


def _fields(cls: type) -> list:
    import dataclasses
    return dataclasses.fields(cls)

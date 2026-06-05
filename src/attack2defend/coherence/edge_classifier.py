"""Edge classifier for the Route Coherence Engine.

Assigns a mapping_basis and provenance score to each edge based on the
source of the relationship (official, mapped, inferred, or conditional).

Scoring table (from plan):
  official_explicit  (+100) NVD explicitly reports CWE for this CVE
  official_related   (+75)  MITRE CWE→CAPEC, CAPEC→ATT&CK, ATT&CK→D3FEND mappings
  analytical_inferred (+35) LLM-proposed + node exists in source; or bundle edge
  conditional        (-25 penalty) context-dependent (e.g. race condition path)
  no source_ref      (-100 penalty)
"""

from __future__ import annotations

from ..coherence.schema import CoherenceEdge, MappingBasis

# Tier weights
_WEIGHTS: dict[str, int] = {
    "official_explicit": 100,
    "official_related": 75,
    "vendor_advisory": 60,
    "bundle_edge": 35,
    "analytical_inferred": 35,
    "conditional": 20,
    "unverified": 0,
}

_CONDITIONAL_PENALTY = 25
_NO_SOURCE_PENALTY = 100


def classify(
    source: str,
    target: str,
    relationship: str,
    basis_hint: str,
    source_refs: list[str],
    notes: str = "",
) -> CoherenceEdge:
    """Build a classified CoherenceEdge from raw mapping data."""
    mapping_basis = _resolve_basis(basis_hint, notes)
    score = _score(mapping_basis, source_refs, notes)
    confidence = _confidence(score)

    return CoherenceEdge(
        source=source,
        target=target,
        relationship=relationship,
        mapping_basis=mapping_basis,
        confidence=confidence,
        score=float(score),
        source_refs=source_refs,
        rationale_es=_rationale(mapping_basis, source, target, relationship),
        notes=notes,
    )


def _resolve_basis(hint: str, notes: str) -> MappingBasis:
    """Normalize basis hint to canonical mapping_basis value."""
    h = hint.lower()
    if "official_explicit" in h or "nvd" in h:
        return "official_explicit"
    if "official_related" in h or "mitre" in h or "capec_mitre" in h or "attack_stix" in h or "d3fend_api" in h or "cwe_mitre" in h:
        return "official_related"
    if "vendor" in h:
        return "official_related"
    if "conditional" in h or "race" in notes.lower() or "conditional" in notes.lower():
        return "conditional"
    if "bundle" in h or "curated" in h:
        return "analytical_inferred"
    if "inferred" in h or "llm" in h:
        return "analytical_inferred"
    return "unverified"


def _score(mapping_basis: MappingBasis, source_refs: list[str], notes: str) -> int:
    base = _WEIGHTS.get(mapping_basis, 0)
    if not source_refs:
        base -= _NO_SOURCE_PENALTY
    if "conditional" in notes.lower() or mapping_basis == "conditional":
        base -= _CONDITIONAL_PENALTY
    return max(0, base)


def _confidence(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "very_low"


def _rationale(basis: str, source: str, target: str, relationship: str) -> str:
    templates: dict[str, str] = {
        "official_explicit": f"{source} → {target}: relación documentada explícitamente en NVD/MITRE ({relationship}).",
        "official_related": f"{source} → {target}: relación derivada de mapping oficial MITRE ({relationship}).",
        "analytical_inferred": f"{source} → {target}: relación analítica inferida; los nodos existen en fuentes oficiales ({relationship}).",
        "conditional": f"{source} → {target}: relación condicional; aplica solo bajo condiciones específicas de explotación ({relationship}).",
        "unverified": f"{source} → {target}: relación no verificada; requiere curaduría ({relationship}).",
    }
    return templates.get(basis, f"{source} → {target} ({relationship})")


def categorize_edges(edges: list[CoherenceEdge]) -> dict[str, list[str]]:
    """Return a dict grouping edge IDs by mapping_basis for the provenance index."""
    groups: dict[str, list[str]] = {
        "official_explicit": [],
        "official_related": [],
        "analytical_inferred": [],
        "conditional": [],
        "unverified": [],
    }
    for edge in edges:
        bucket = groups.get(edge.mapping_basis, "unverified")
        if isinstance(bucket, list):
            bucket.append(edge.edge_id)
        else:
            groups.setdefault(edge.mapping_basis, []).append(edge.edge_id)
    return groups

"""Incremental enrichment layer for Attack2Defend."""

from .route_enrichment import (
    EnrichmentResult,
    build_enrichment_result,
    build_grounded_synthesis,
    coverage_gap_report,
    merge_bundle,
    merge_bundle_with_stats,
    normalize_route_input,
    validate_synthesis,
    write_knowledge_store,
)

__all__ = [
    "EnrichmentResult",
    "build_enrichment_result",
    "build_grounded_synthesis",
    "coverage_gap_report",
    "merge_bundle",
    "merge_bundle_with_stats",
    "normalize_route_input",
    "validate_synthesis",
    "write_knowledge_store",
]

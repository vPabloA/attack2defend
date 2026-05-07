from attack2defend.capability import resolve_defense_route
from attack2defend.intelligence import CURATED_ROUTE_LIMITS, build_curated_route, build_official_context_pack


BUNDLE = "data/knowledge-bundle.json"
GOLDEN_INPUTS = [
    "CVE-2021-44228",
    "CVE-2024-37079",
    "T1190",
]


def test_golden_curated_routes_keep_limits_and_do_not_invent_ids():
    for value in GOLDEN_INPUTS:
        capability = resolve_defense_route({"input": value}, bundle_path=BUNDLE)
        context = build_official_context_pack(capability)
        allowed_ids = {entry["id"] for entry in context["entries"]}
        route = build_curated_route(capability, context)

        assert route["validation"]["status"] == "pass"
        assert route["runtime_public_api_calls"] is False
        assert route["mode"] == "official_rag_grounded"
        assert route["selection_method"] == "deterministic_prefilter"
        assert route["full_traceability_counts"] == context["full_traceability_counts"]

        for stage in route["stages"]:
            assert len(stage["selected"]) <= CURATED_ROUTE_LIMITS[stage["type"]]
            for item in stage["selected"]:
                assert item["id"] in allowed_ids
                assert item["reason_es"]

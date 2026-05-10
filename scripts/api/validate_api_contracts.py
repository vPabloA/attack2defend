#!/usr/bin/env python3
"""Validate read-only API automation contracts without starting a server."""
from __future__ import annotations

from attack2defend.automation.service import AutomationService
from attack2defend.automation.schemas import SOAR_SAFE_FIELDS, SOC_ACTION_PACK_FIELDS


def assert_soar_safe(payload: dict) -> None:
    for field in SOAR_SAFE_FIELDS:
        assert field in payload, f"missing SOAR-safe field: {field}"
    assert payload["blocking"] is False
    assert payload["timeout_waited_for_human"] is False


def main() -> int:
    service = AutomationService()
    checks = [
        service.health(),
        service.metadata(),
        service.resolve_route("CVE-2021-44228"),
        service.batch_resolve_route(["CVE-2021-44228"]),
        service.get_factory_status(),
        service.get_golden_evaluation(),
        service.get_graph_quality(),
        service.policy_inspect(),
        service.search_knowledge("CVE"),
    ]
    soc = service.build_soc_action_pack("CVE-2021-44228")
    checks.append(soc)
    for payload in checks:
        assert_soar_safe(payload)
    soc_pack = soc.get("soc_pack", {})
    for field in SOC_ACTION_PACK_FIELDS:
        assert field in soc_pack, f"missing SOC action pack field: {field}"
    assert soc.get("audit", {}).get("source_of_truth") == "knowledge-bundle.json"
    assert soc.get("audit", {}).get("external_calls") is False
    print("validate-api: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

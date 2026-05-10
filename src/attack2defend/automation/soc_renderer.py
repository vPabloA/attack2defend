"""SOC-actionable rendering helpers."""
from __future__ import annotations

from .service import AutomationService


def build_soc_action_pack(identifier: str) -> dict:
    return AutomationService().build_soc_action_pack(identifier)


def explain_d3fend_for_soc(d3fend_id: str) -> dict:
    return AutomationService().explain_d3fend_for_soc(d3fend_id)


def get_top_mitigations(identifier: str) -> dict:
    return AutomationService().get_top_mitigations(identifier)

"""Provenance audit facade."""
from __future__ import annotations

from .service import AutomationService


def audit_provenance(identifier: str) -> dict:
    return AutomationService().audit_provenance(identifier)


def get_evidence_pack(identifier: str) -> dict:
    return AutomationService().get_evidence_pack(identifier)

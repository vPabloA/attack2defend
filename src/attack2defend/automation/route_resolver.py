"""Route resolver facade for compatibility with automation consumers."""
from __future__ import annotations

from .service import AutomationService


def resolve_route(identifier: str, depth: int = 8) -> dict:
    return AutomationService().resolve_route(identifier, depth=depth)


def batch_resolve_route(identifiers: list[str]) -> dict:
    return AutomationService().batch_resolve_route(identifiers)

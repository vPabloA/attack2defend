"""Local graph exploration facade."""
from __future__ import annotations

from .service import AutomationService


def graph_explore(identifier: str, depth: int = 2, direction: str = "both") -> dict:
    return AutomationService().graph_explore(identifier, depth=depth, direction=direction)


def get_graph_quality() -> dict:
    return AutomationService().get_graph_quality()

"""Attack2Defend automation service layer.

Read-only helpers for API, MCP and CLI surfaces. The canonical source of truth
remains data/knowledge-bundle.json.
"""

from .service import AutomationService

__all__ = ["AutomationService"]

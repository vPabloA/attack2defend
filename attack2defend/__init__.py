"""Source-tree import shim for fresh checkouts.

The project uses a ``src`` layout. This shim lets repo-root commands such as
``python -m attack2defend.api.app`` run before an editable install, while the
actual package implementation remains under ``src/attack2defend``.
"""
from __future__ import annotations

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "attack2defend"
__path__ = [str(_SRC_PACKAGE)]
__file__ = str(_SRC_PACKAGE / "__init__.py")

with open(__file__, "r", encoding="utf-8") as _source_file:
    exec(compile(_source_file.read(), __file__, "exec"), globals())

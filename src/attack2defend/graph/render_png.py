"""PNG renderer for Route Coherence Knowledge Graph.

Converts an SVG string to PNG. Tries these backends in order:
  1. cairosvg (if installed) — preferred, pure Python
  2. Pillow + cairosvg fallback
  3. Write SVG bytes and log a warning if no renderer is available

The caller always gets a bytes object. If no rasterizer is installed,
returns the SVG bytes with a .svg content-type so the caller can still save.
"""

from __future__ import annotations

import warnings


def svg_to_png(svg_str: str, scale: float = 1.5) -> bytes:
    """Convert SVG string to PNG bytes. Falls back to SVG bytes if unavailable."""
    try:
        import cairosvg  # type: ignore[import-untyped]
        return cairosvg.svg2png(bytestring=svg_str.encode("utf-8"), scale=scale)
    except ImportError:
        pass

    try:
        from PIL import Image  # type: ignore[import-untyped]
        import io
        # Try Pillow's SVG support (requires librsvg or similar)
        img = Image.open(io.BytesIO(svg_str.encode("utf-8")))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        pass

    warnings.warn(
        "No SVG rasterizer available (cairosvg or Pillow+rsvg). "
        "Saving SVG bytes instead of PNG. Install 'cairosvg' for PNG export: pip install cairosvg",
        stacklevel=2,
    )
    return svg_str.encode("utf-8")


def is_png_available() -> bool:
    try:
        import cairosvg  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        pass
    return False

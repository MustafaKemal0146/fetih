"""``python -m fetih_desktop_bridge`` — same entry point as ``fetih desktop-bridge``."""

from __future__ import annotations

from .entry import main

if __name__ == "__main__":
    raise SystemExit(main())

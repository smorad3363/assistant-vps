"""Port Manager V2 (development bootstrap)."""

from pathlib import Path

VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text(
    encoding="utf-8"
).strip()
